package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/internal/audit"
	"github.com/misbakhul29/backend-framework/internal/auth/mfa"
	"github.com/misbakhul29/backend-framework/internal/auth/oauth"
	"github.com/misbakhul29/backend-framework/pkg/db"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"github.com/misbakhul29/backend-framework/pkg/errs"
	"github.com/misbakhul29/backend-framework/pkg/httpx"
	"github.com/misbakhul29/backend-framework/pkg/security"
)

var (
	ErrUserAlreadyExists    = errs.NewDomainError(string(errs.ErrCodeConflict), "user already exists", nil)
	ErrInvalidCredentials   = errs.NewDomainError(string(errs.ErrCodeInvalidCredentials), "invalid credentials", nil)
	ErrUserNotFound         = errs.NewDomainError(string(errs.ErrCodeNotFound), "user not found", nil)
	ErrInternalServer       = errs.NewDomainError(string(errs.ErrCodeInternalError), "internal server error", nil)
	ErrMFAChallengeRequired = errs.NewDomainError("MFA_CHALLENGE_REQUIRED", "mfa verification required", nil)
	ErrInvalidMFACode       = errs.NewDomainError("INVALID_MFA_CODE", "invalid mfa code or recovery code", nil)
)

type ClientInfo struct {
	IPAddress string
	UserAgent string
	Device    string
}

type SessionInfo struct {
	ID           string     `json:"id"`
	IPAddress    *string    `json:"ip_address,omitempty"`
	UserAgent    *string    `json:"user_agent,omitempty"`
	Device       *string    `json:"device,omitempty"`
	IsCurrent    bool       `json:"is_current"`
	LastActiveAt *time.Time `json:"last_active_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
}

type AuthService interface {
	Register(ctx context.Context, name, email, password string) (*models.User, error)
	Login(ctx context.Context, email, password string, clientInfo ...ClientInfo) (*models.User, *security.IssuedTokens, error)
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	ChangePassword(ctx context.Context, userID, oldPassword, newPassword string, revokeOtherSessions bool, currentSessionID string) error
	RefreshToken(ctx context.Context, rawRefreshToken string) (*security.IssuedTokens, error)
	ListActiveSessions(ctx context.Context, userID, currentSessionID string) ([]SessionInfo, error)
	RevokeSession(ctx context.Context, sessionID, userID string) error
	RevokeAllSessions(ctx context.Context, userID, currentSessionID string, excludeCurrent bool) (int64, error)
	GetMe(ctx context.Context, userID string) (*models.User, error)
	Logout(ctx context.Context, sessionID string) error
	ChangeRole(ctx context.Context, targetUserID, roleName string) error

	// OAuth2 and SSO
	OAuthLoginOrLink(ctx context.Context, profile *oauth.UserProfile, clientInfo ...ClientInfo) (*models.User, *security.IssuedTokens, error)

	// Two-Factor Authentication (2FA/TOTP)
	SetupMFA(ctx context.Context, userID, appName string) (*mfa.TOTPSetupData, error)
	VerifyAndEnableMFA(ctx context.Context, userID, code string) error
	VerifyMFALogin(ctx context.Context, mfaToken, code string, clientInfo ...ClientInfo) (*models.User, *security.IssuedTokens, error)
	DisableMFA(ctx context.Context, userID, code string) error

	SetMFAService(mfaSvc mfa.MFAService)
	SetAuditService(auditSvc audit.Service)
}

type AuthServiceImpl struct {
	repo        AuthRepository
	gormDB      *gorm.DB
	redisClient *redis.Client
	jwtCfg      config.JWT
	mfaSvc      mfa.MFAService
	auditSvc    audit.Service
}

func NewService(repo AuthRepository, gormDB *gorm.DB, redisClient *redis.Client, jwtCfg config.JWT) *AuthServiceImpl {
	return &AuthServiceImpl{
		repo:        repo,
		gormDB:      gormDB,
		redisClient: redisClient,
		jwtCfg:      jwtCfg,
		mfaSvc:      mfa.NewMFAService(),
	}
}

func (s *AuthServiceImpl) SetMFAService(mfaSvc mfa.MFAService) {
	s.mfaSvc = mfaSvc
}

func (s *AuthServiceImpl) SetAuditService(auditSvc audit.Service) {
	s.auditSvc = auditSvc
}

func (s *AuthServiceImpl) Register(ctx context.Context, name, email, password string) (*models.User, error) {
	normEmail := strings.ToLower(strings.TrimSpace(email))
	trimmedName := strings.TrimSpace(name)

	if err := security.ValidateEmail(normEmail); err != nil {
		return nil, httpx.ErrValidation
	}
	if err := security.ValidatePasswordStrength(password); err != nil {
		return nil, httpx.ErrValidation
	}

	_, err := s.repo.GetUserByEmail(ctx, normEmail)
	if err == nil {
		return nil, ErrUserAlreadyExists
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrInternalServer
	}

	hashedPassword, err := security.HashPassword(password)
	if err != nil {
		return nil, ErrInternalServer
	}

	userID := uuid.NewString()
	now := time.Now()

	user := &models.User{
		ID:            userID,
		Name:          trimmedName,
		Email:         normEmail,
		EmailVerified: false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	err = db.WithTx(ctx, s.gormDB, func(txCtx context.Context, tx *gorm.DB) error {
		memberRole, err := s.repo.GetRoleByName(txCtx, models.DefaultRole)
		if err != nil {
			return err
		}
		user.Roles = []models.Role{*memberRole}

		if err := s.repo.CreateUser(txCtx, user); err != nil {
			return err
		}

		account := &models.Account{
			ID:         uuid.NewString(),
			AccountID:  normEmail,
			ProviderID: "credentials",
			UserID:     userID,
			Password:   &hashedPassword,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		return s.repo.CreateAccount(txCtx, account)
	})

	if err != nil {
		return nil, ErrInternalServer
	}

	return user, nil
}

func (s *AuthServiceImpl) Login(ctx context.Context, email, password string, clientInfo ...ClientInfo) (*models.User, *security.IssuedTokens, error) {
	normEmail := strings.ToLower(strings.TrimSpace(email))

	lockoutKey := normEmail
	lockRes, err := security.CheckLockout(ctx, s.redisClient, lockoutKey)
	if err != nil {
		return nil, nil, ErrInternalServer
	}
	if !lockRes.Allowed {
		return nil, nil, httpx.ErrAccountLocked
	}

	user, err := s.repo.GetUserByEmail(ctx, normEmail)
	if err != nil {
		// Run dummy verification to eliminate user-enumeration timing leaks
		security.DummyVerifyPassword(password)
		_, _, _ = security.RecordFailedAttempt(ctx, s.redisClient, lockoutKey)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, ErrInternalServer
	}

	account, err := s.repo.GetAccountByUserIDAndProvider(ctx, user.ID, "credentials")
	if err != nil || account.Password == nil {
		security.DummyVerifyPassword(password)
		_, _, _ = security.RecordFailedAttempt(ctx, s.redisClient, lockoutKey)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, ErrInternalServer
	}

	match, err := security.VerifyPassword(password, *account.Password)
	if err != nil || !match {
		_, _, _ = security.RecordFailedAttempt(ctx, s.redisClient, lockoutKey)
		return nil, nil, ErrInvalidCredentials
	}

	_ = security.ResetFailedAttempts(ctx, s.redisClient, lockoutKey)

	if user.MfaEnabled {
		challengeToken, err := s.generateMFAChallengeToken(user.ID)
		if err != nil {
			return nil, nil, ErrInternalServer
		}
		return user, &security.IssuedTokens{
			AccessToken: challengeToken,
		}, ErrMFAChallengeRequired
	}

	issued, err := s.issueSessionTokens(ctx, user, clientInfo)
	if err != nil {
		return nil, nil, err
	}

	if s.auditSvc != nil {
		_ = s.auditSvc.Log(ctx, audit.Event{
			EventType: audit.EventLoginSuccess,
			Status:    "SUCCESS",
			UserID:    &user.ID,
		})
	}

	return user, issued, nil
}

func (s *AuthServiceImpl) ForgotPassword(ctx context.Context, email string) error {
	normEmail := strings.ToLower(strings.TrimSpace(email))
	if err := security.ValidateEmail(normEmail); err != nil {
		return httpx.ErrValidation
	}

	user, err := s.repo.GetUserByEmail(ctx, normEmail)
	if err != nil {
		// Generic success to prevent account enumeration
		return nil
	}

	rawToken, err := security.GenerateOpaqueToken(32)
	if err != nil {
		return ErrInternalServer
	}
	tokenHash := security.HashToken(rawToken)

	now := time.Now()
	verification := &models.Verification{
		ID:         uuid.NewString(),
		Identifier: user.ID,
		Value:      tokenHash,
		ExpiresAt:  now.Add(15 * time.Minute),
		CreatedAt:  &now,
		UpdatedAt:  &now,
	}

	err = db.WithTx(ctx, s.gormDB, func(txCtx context.Context, tx *gorm.DB) error {
		_ = s.repo.DeleteVerificationsByIdentifier(txCtx, user.ID)
		return s.repo.CreateVerification(txCtx, verification)
	})
	if err != nil {
		return ErrInternalServer
	}

	return nil
}

func (s *AuthServiceImpl) ResetPassword(ctx context.Context, token, newPassword string) error {
	if token == "" {
		return httpx.ErrValidation
	}
	if err := security.ValidatePasswordStrength(newPassword); err != nil {
		return httpx.ErrValidation
	}

	tokenHash := security.HashToken(token)
	v, err := s.repo.GetVerificationByValue(ctx, tokenHash)
	if err != nil || time.Now().After(v.ExpiresAt) {
		return httpx.ErrInvalidToken
	}

	account, err := s.repo.GetAccountByUserIDAndProvider(ctx, v.Identifier, "credentials")
	if err != nil {
		return httpx.ErrInvalidToken
	}

	newHash, err := security.HashPassword(newPassword)
	if err != nil {
		return ErrInternalServer
	}

	err = db.WithTx(ctx, s.gormDB, func(txCtx context.Context, tx *gorm.DB) error {
		if err := s.repo.UpdateAccountPassword(txCtx, account.ID, newHash); err != nil {
			return err
		}
		if err := s.repo.DeleteVerification(txCtx, v.ID); err != nil {
			return err
		}
		return s.repo.RevokeUserSessions(txCtx, v.Identifier, "")
	})
	if err != nil {
		return ErrInternalServer
	}

	return nil
}

func (s *AuthServiceImpl) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string, revokeOtherSessions bool, currentSessionID string) error {
	if err := security.ValidatePasswordStrength(newPassword); err != nil {
		return httpx.ErrValidation
	}

	account, err := s.repo.GetAccountByUserIDAndProvider(ctx, userID, "credentials")
	if err != nil || account.Password == nil {
		return ErrInvalidCredentials
	}

	match, err := security.VerifyPassword(oldPassword, *account.Password)
	if err != nil || !match {
		return ErrInvalidCredentials
	}

	newHash, err := security.HashPassword(newPassword)
	if err != nil {
		return ErrInternalServer
	}

	err = db.WithTx(ctx, s.gormDB, func(txCtx context.Context, tx *gorm.DB) error {
		if err := s.repo.UpdateAccountPassword(txCtx, account.ID, newHash); err != nil {
			return err
		}
		if revokeOtherSessions {
			return s.repo.RevokeUserSessions(txCtx, userID, currentSessionID)
		}
		return nil
	})
	if err != nil {
		return ErrInternalServer
	}

	return nil
}

func (s *AuthServiceImpl) RefreshToken(ctx context.Context, rawRefreshToken string) (*security.IssuedTokens, error) {
	if rawRefreshToken == "" {
		return nil, httpx.ErrValidation
	}

	tokenHash := security.HashToken(rawRefreshToken)

	tokenRecord, err := s.repo.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, httpx.ErrUnauthorized
		}
		return nil, ErrInternalServer
	}

	// Invalidate token lineage and parent sessions immediately if reuse is detected.
	if tokenRecord.IsRevoked {
		_ = db.WithTx(ctx, s.gormDB, func(txCtx context.Context, tx *gorm.DB) error {
			_ = s.repo.RevokeTokenFamily(txCtx, tokenRecord.FamilyID)
			_ = s.repo.RevokeSession(txCtx, tokenRecord.SessionID)
			if tokenRecord.FamilyID != "" {
				_ = s.repo.RevokeFamilySessions(txCtx, tokenRecord.FamilyID)
			}
			return nil
		})
		return nil, httpx.ErrTokenReuseDetected
	}

	now := time.Now()
	if now.After(tokenRecord.ExpiresAt) {
		_ = db.WithTx(ctx, s.gormDB, func(txCtx context.Context, tx *gorm.DB) error {
			_, err := s.repo.RevokeRefreshToken(txCtx, tokenRecord.ID, nil)
			return err
		})
		return nil, httpx.ErrUnauthorized
	}

	if tokenRecord.Session.ID == "" || tokenRecord.Session.IsRevoked || now.After(tokenRecord.Session.ExpiresAt) {
		return nil, httpx.ErrUnauthorized
	}

	user, err := s.repo.GetUserByID(ctx, tokenRecord.Session.UserID)
	if err != nil || !user.IsActive {
		return nil, httpx.ErrUnauthorized
	}

	newRawToken, err := security.GenerateOpaqueToken(32)
	if err != nil {
		return nil, ErrInternalServer
	}
	newTokenHash := security.HashToken(newRawToken)
	newTokenID := uuid.NewString()

	tokenConfig := security.TokenConfig{
		Secret:     []byte(s.jwtCfg.Secret),
		AccessTTL:  time.Duration(s.jwtCfg.AccessTTL) * time.Second,
		RefreshTTL: time.Duration(s.jwtCfg.RefreshTTL) * time.Second,
	}

	newRecord := &models.RefreshToken{
		ID:        newTokenID,
		SessionID: tokenRecord.SessionID,
		FamilyID:  tokenRecord.FamilyID,
		TokenHash: newTokenHash,
		IsRevoked: false,
		ExpiresAt: now.Add(tokenConfig.RefreshTTL),
		CreatedAt: now,
	}

	perms, err := s.repo.GetUserPermissions(ctx, user.ID)
	if err != nil {
		return nil, ErrInternalServer
	}

	var reuseDetected bool
	err = db.WithTx(ctx, s.gormDB, func(txCtx context.Context, tx *gorm.DB) error {
		revoked, err := s.repo.RevokeRefreshToken(txCtx, tokenRecord.ID, &newTokenID)
		if err != nil {
			return err
		}
		if !revoked {
			reuseDetected = true
			if err := s.repo.RevokeTokenFamily(txCtx, tokenRecord.FamilyID); err != nil {
				return err
			}
			if err := s.repo.RevokeSession(txCtx, tokenRecord.SessionID); err != nil {
				return err
			}
			if tokenRecord.FamilyID != "" {
				if err := s.repo.RevokeFamilySessions(txCtx, tokenRecord.FamilyID); err != nil {
					return err
				}
			}
			return nil
		}

		if err := s.repo.CreateRefreshToken(txCtx, newRecord); err != nil {
			return err
		}
		if err := s.repo.UpdateSessionTokenHash(txCtx, tokenRecord.SessionID, newTokenHash); err != nil {
			return err
		}
		return s.repo.UpdateSessionLastActive(txCtx, tokenRecord.SessionID)
	})
	if err != nil {
		return nil, ErrInternalServer
	}
	if reuseDetected {
		return nil, httpx.ErrTokenReuseDetected
	}

	roleName := models.RoleMember
	issued, err := security.IssueTokenPair(tokenConfig, user.ID, user.ID, tokenRecord.SessionID, roleName, []string{"refresh"}, perms)
	if err != nil {
		return nil, ErrInternalServer
	}
	issued.RefreshToken = newRawToken

	return issued, nil
}

func (s *AuthServiceImpl) ListActiveSessions(ctx context.Context, userID, currentSessionID string) ([]SessionInfo, error) {
	sessions, err := s.repo.GetActiveSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, ErrInternalServer
	}

	result := make([]SessionInfo, len(sessions))
	for i, session := range sessions {
		result[i] = SessionInfo{
			ID:           session.ID,
			IPAddress:    session.IPAddress,
			UserAgent:    session.UserAgent,
			Device:       session.Device,
			IsCurrent:    session.ID == currentSessionID,
			LastActiveAt: session.LastActiveAt,
			CreatedAt:    session.CreatedAt,
			ExpiresAt:    session.ExpiresAt,
		}
	}
	return result, nil
}

func (s *AuthServiceImpl) RevokeSession(ctx context.Context, sessionID, userID string) error {
	err := s.repo.RevokeSessionByID(ctx, sessionID, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return httpx.ErrNotFound
		}
		return ErrInternalServer
	}
	return nil
}

func (s *AuthServiceImpl) RevokeAllSessions(ctx context.Context, userID, currentSessionID string, excludeCurrent bool) (int64, error) {
	excludeID := ""
	if excludeCurrent {
		excludeID = currentSessionID
	}
	count, err := s.repo.RevokeSessionsByUserID(ctx, userID, excludeID)
	if err != nil {
		return 0, ErrInternalServer
	}
	return count, nil
}

func (s *AuthServiceImpl) GetMe(ctx context.Context, userID string) (*models.User, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, ErrInternalServer
	}
	return user, nil
}

func (s *AuthServiceImpl) Logout(ctx context.Context, sessionID string) error {
	_ = s.repo.RevokeSession(ctx, sessionID)
	_ = s.repo.DeleteSession(ctx, sessionID)
	return nil
}

func (s *AuthServiceImpl) ChangeRole(ctx context.Context, targetUserID, roleName string) error {
	_, err := s.repo.GetUserByID(ctx, targetUserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return ErrInternalServer
	}

	err = s.repo.UpdateUserRole(ctx, targetUserID, roleName)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errs.NewDomainError(string(errs.ErrCodeBadRequest), "role not found", nil)
		}
		return ErrInternalServer
	}

	return nil
}

func (s *AuthServiceImpl) issueSessionTokens(ctx context.Context, user *models.User, clientInfo []ClientInfo) (*security.IssuedTokens, error) {
	tokenConfig := security.TokenConfig{
		Secret:     []byte(s.jwtCfg.Secret),
		AccessTTL:  time.Duration(s.jwtCfg.AccessTTL) * time.Second,
		RefreshTTL: time.Duration(s.jwtCfg.RefreshTTL) * time.Second,
	}

	perms, err := s.repo.GetUserPermissions(ctx, user.ID)
	if err != nil {
		return nil, ErrInternalServer
	}

	sessionID := uuid.NewString()
	familyID := uuid.NewString()

	rawRefreshToken, err := security.GenerateOpaqueToken(32)
	if err != nil {
		return nil, ErrInternalServer
	}
	tokenHash := security.HashToken(rawRefreshToken)

	roleName := models.RoleMember
	if len(user.Roles) > 0 && user.Roles[0].Name != "" {
		roleName = user.Roles[0].Name
	}

	issued, err := security.IssueTokenPair(tokenConfig, user.ID, user.ID, sessionID, roleName, []string{"password"}, perms)
	if err != nil {
		return nil, ErrInternalServer
	}
	issued.RefreshToken = rawRefreshToken

	now := time.Now()
	var ipPtr, uaPtr, devPtr *string
	if len(clientInfo) > 0 {
		if clientInfo[0].IPAddress != "" {
			ip := clientInfo[0].IPAddress
			ipPtr = &ip
		}
		if clientInfo[0].UserAgent != "" {
			ua := clientInfo[0].UserAgent
			uaPtr = &ua
		}
		if clientInfo[0].Device != "" {
			dev := clientInfo[0].Device
			devPtr = &dev
		}
	}

	session := &models.Session{
		ID:           sessionID,
		ExpiresAt:    now.Add(tokenConfig.RefreshTTL),
		TokenHash:    tokenHash,
		FamilyID:     familyID,
		IsRevoked:    false,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: &now,
		IPAddress:    ipPtr,
		UserAgent:    uaPtr,
		Device:       devPtr,
		UserID:       user.ID,
	}

	refreshTokenRecord := &models.RefreshToken{
		ID:        uuid.NewString(),
		SessionID: sessionID,
		FamilyID:  familyID,
		TokenHash: tokenHash,
		IsRevoked: false,
		ExpiresAt: now.Add(tokenConfig.RefreshTTL),
		CreatedAt: now,
	}

	err = db.WithTx(ctx, s.gormDB, func(txCtx context.Context, tx *gorm.DB) error {
		if err := s.repo.CreateSession(txCtx, session); err != nil {
			return err
		}
		return s.repo.CreateRefreshToken(txCtx, refreshTokenRecord)
	})
	if err != nil {
		return nil, ErrInternalServer
	}

	return issued, nil
}

func (s *AuthServiceImpl) generateMFAChallengeToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub":  userID,
		"type": "mfa_challenge",
		"exp":  time.Now().Add(5 * time.Minute).Unix(),
		"iat":  time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtCfg.Secret))
}

func (s *AuthServiceImpl) parseMFAChallengeToken(tokenStr string) (string, error) {
	parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.jwtCfg.Secret), nil
	})
	if err != nil || !parsed.Valid {
		return "", errors.New("invalid or expired mfa challenge token")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || claims["type"] != "mfa_challenge" {
		return "", errors.New("invalid token type")
	}
	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		return "", errors.New("missing subject in token")
	}
	return userID, nil
}

func (s *AuthServiceImpl) OAuthLoginOrLink(ctx context.Context, profile *oauth.UserProfile, clientInfo ...ClientInfo) (*models.User, *security.IssuedTokens, error) {
	if profile == nil || profile.ProviderID == "" || profile.AccountID == "" {
		return nil, nil, errs.NewDomainError(string(errs.ErrCodeBadRequest), "invalid oauth profile", nil)
	}

	var user *models.User
	now := time.Now()

	account, err := s.repo.GetAccountByProviderAndAccountID(ctx, profile.ProviderID, profile.AccountID)
	if err == nil {
		user, err = s.repo.GetUserByID(ctx, account.UserID)
		if err != nil {
			return nil, nil, ErrInternalServer
		}
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		if profile.Email != "" {
			existingUser, err := s.repo.GetUserByEmail(ctx, profile.Email)
			if err == nil {
				user = existingUser
				newAccount := &models.Account{
					ID:         uuid.NewString(),
					AccountID:  profile.AccountID,
					ProviderID: profile.ProviderID,
					UserID:     user.ID,
					CreatedAt:  now,
					UpdatedAt:  now,
				}
				if err := s.repo.CreateAccount(ctx, newAccount); err != nil {
					return nil, nil, ErrInternalServer
				}
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, nil, ErrInternalServer
			}
		}

		if user == nil {
			userID := uuid.NewString()
			userName := profile.Name
			if userName == "" {
				userName = profile.Email
			}
			userEmail := profile.Email
			if userEmail == "" {
				userEmail = fmt.Sprintf("%s_%s@oauth.local", profile.ProviderID, profile.AccountID)
			}

			user = &models.User{
				ID:            userID,
				Name:          userName,
				Email:         userEmail,
				EmailVerified: profile.EmailVerified,
				Image:         &profile.AvatarURL,
				CreatedAt:     now,
				UpdatedAt:     now,
			}

			err = db.WithTx(ctx, s.gormDB, func(txCtx context.Context, tx *gorm.DB) error {
				memberRole, err := s.repo.GetRoleByName(txCtx, models.DefaultRole)
				if err != nil {
					return err
				}
				user.Roles = []models.Role{*memberRole}
				if err := s.repo.CreateUser(txCtx, user); err != nil {
					return err
				}
				newAccount := &models.Account{
					ID:         uuid.NewString(),
					AccountID:  profile.AccountID,
					ProviderID: profile.ProviderID,
					UserID:     userID,
					CreatedAt:  now,
					UpdatedAt:  now,
				}
				return s.repo.CreateAccount(txCtx, newAccount)
			})
			if err != nil {
				return nil, nil, ErrInternalServer
			}
		}
	} else {
		return nil, nil, ErrInternalServer
	}

	tokens, err := s.issueSessionTokens(ctx, user, clientInfo)
	if err != nil {
		return nil, nil, err
	}

	if s.auditSvc != nil {
		_ = s.auditSvc.Log(ctx, audit.Event{
			EventType: audit.EventOAuthLogin,
			Status:    "SUCCESS",
			UserID:    &user.ID,
			Metadata: map[string]any{
				"provider": profile.ProviderID,
				"email":    user.Email,
			},
		})
	}

	return user, tokens, nil
}

func (s *AuthServiceImpl) SetupMFA(ctx context.Context, userID, appName string) (*mfa.TOTPSetupData, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if appName == "" {
		appName = "Backend Framework"
	}

	setupData, hashedCodes, err := s.mfaSvc.GenerateSecret(appName, user.Email)
	if err != nil {
		return nil, ErrInternalServer
	}

	if err := s.repo.UpdateUserMFA(ctx, userID, false, &setupData.Secret); err != nil {
		return nil, ErrInternalServer
	}

	_ = s.repo.DeleteUserBackupCodes(ctx, userID)
	now := time.Now()
	backupRecords := make([]models.MfaBackupCode, len(hashedCodes))
	for i, h := range hashedCodes {
		backupRecords[i] = models.MfaBackupCode{
			ID:        uuid.NewString(),
			UserID:    userID,
			CodeHash:  h,
			IsUsed:    false,
			CreatedAt: now,
		}
	}
	if err := s.repo.CreateBackupCodes(ctx, backupRecords); err != nil {
		return nil, ErrInternalServer
	}

	return setupData, nil
}

func (s *AuthServiceImpl) VerifyAndEnableMFA(ctx context.Context, userID, code string) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}
	if user.MfaSecret == nil || *user.MfaSecret == "" {
		return errs.NewDomainError(string(errs.ErrCodeBadRequest), "mfa setup not initiated", nil)
	}

	if !s.mfaSvc.VerifyCode(*user.MfaSecret, code) {
		return ErrInvalidMFACode
	}

	if err := s.repo.UpdateUserMFA(ctx, userID, true, user.MfaSecret); err != nil {
		return ErrInternalServer
	}

	if s.auditSvc != nil {
		_ = s.auditSvc.Log(ctx, audit.Event{
			EventType: audit.EventMFASetup,
			Status:    "SUCCESS",
			UserID:    &userID,
		})
	}

	return nil
}

func (s *AuthServiceImpl) VerifyMFALogin(ctx context.Context, mfaToken, code string, clientInfo ...ClientInfo) (*models.User, *security.IssuedTokens, error) {
	userID, err := s.parseMFAChallengeToken(mfaToken)
	if err != nil {
		return nil, nil, errs.NewDomainError(string(errs.ErrCodeUnauthorized), err.Error(), nil)
	}

	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, nil, ErrUserNotFound
	}

	if !user.MfaEnabled || user.MfaSecret == nil {
		return nil, nil, errs.NewDomainError(string(errs.ErrCodeBadRequest), "mfa is not enabled for this user", nil)
	}

	valid := s.mfaSvc.VerifyCode(*user.MfaSecret, code)
	if !valid {
		unused, err := s.repo.GetUnusedBackupCodes(ctx, userID)
		if err == nil && len(unused) > 0 {
			hashes := make([]string, len(unused))
			for i, c := range unused {
				hashes[i] = c.CodeHash
			}
			matched, idx := s.mfaSvc.VerifyRecoveryCode(code, hashes)
			if matched && idx >= 0 {
				_ = s.repo.MarkBackupCodeUsed(ctx, unused[idx].ID)
				valid = true
			}
		}
	}

	if !valid {
		return nil, nil, ErrInvalidMFACode
	}

	tokens, err := s.issueSessionTokens(ctx, user, clientInfo)
	if err != nil {
		return nil, nil, err
	}

	if s.auditSvc != nil {
		_ = s.auditSvc.Log(ctx, audit.Event{
			EventType: audit.EventMFAVerify,
			Status:    "SUCCESS",
			UserID:    &userID,
		})
	}

	return user, tokens, nil
}

func (s *AuthServiceImpl) DisableMFA(ctx context.Context, userID, code string) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}
	if !user.MfaEnabled || user.MfaSecret == nil {
		return errs.NewDomainError(string(errs.ErrCodeBadRequest), "mfa is not enabled", nil)
	}

	if !s.mfaSvc.VerifyCode(*user.MfaSecret, code) {
		return ErrInvalidMFACode
	}

	if err := s.repo.UpdateUserMFA(ctx, userID, false, nil); err != nil {
		return ErrInternalServer
	}
	_ = s.repo.DeleteUserBackupCodes(ctx, userID)

	if s.auditSvc != nil {
		_ = s.auditSvc.Log(ctx, audit.Event{
			EventType: audit.EventMFADisabled,
			Status:    "SUCCESS",
			UserID:    &userID,
		})
	}

	return nil
}
