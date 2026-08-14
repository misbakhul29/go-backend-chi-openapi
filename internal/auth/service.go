package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/pkg/db"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"github.com/misbakhul29/backend-framework/pkg/errs"
	"github.com/misbakhul29/backend-framework/pkg/security"
)

var (
	ErrUserAlreadyExists  = errs.NewDomainError(string(errs.ErrCodeConflict), "user already exists", nil)
	ErrInvalidCredentials = errs.NewDomainError(string(errs.ErrCodeInvalidCredentials), "invalid credentials", nil)
	ErrUserNotFound       = errs.NewDomainError(string(errs.ErrCodeNotFound), "user not found", nil)
	ErrInternalServer     = errs.NewDomainError(string(errs.ErrCodeInternalError), "internal server error", nil)
)

type AuthService interface {
	Register(ctx context.Context, name, email, password string) (*models.User, error)
	Login(ctx context.Context, email, password string) (*models.User, *security.IssuedTokens, error)
	GetMe(ctx context.Context, userID string) (*models.User, error)
	Logout(ctx context.Context, sessionID string) error
	ChangeRole(ctx context.Context, targetUserID, roleName string) error
}

type AuthServiceImpl struct {
	repo   AuthRepository
	gormDB *gorm.DB
	jwtCfg config.JWT
}

func NewService(repo AuthRepository, gormDB *gorm.DB, jwtCfg config.JWT) *AuthServiceImpl {
	return &AuthServiceImpl{
		repo:   repo,
		gormDB: gormDB,
		jwtCfg: jwtCfg,
	}
}

func (s *AuthServiceImpl) Register(ctx context.Context, name, email, password string) (*models.User, error) {
	// Check if user already exists
	_, err := s.repo.GetUserByEmail(ctx, email)
	if err == nil {
		return nil, ErrUserAlreadyExists
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrInternalServer
	}

	// Hash password using Argon2id helper
	hashedPassword, err := security.HashPassword(password)
	if err != nil {
		return nil, ErrInternalServer
	}

	userID := uuid.NewString()
	now := time.Now()

	user := &models.User{
		ID:            userID,
		Name:          name,
		Email:         email,
		EmailVerified: false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	// Propagate transaction-bound context txCtx to repository operations
	err = db.WithTx(ctx, s.gormDB, func(txCtx context.Context, tx *gorm.DB) error {
		// Fetch ADMIN role
		adminRole, err := s.repo.GetRoleByName(txCtx, "ADMIN")
		if err != nil {
			return err
		}
		user.Roles = []models.Role{*adminRole}

		if err := s.repo.CreateUser(txCtx, user); err != nil {
			return err
		}

		account := &models.Account{
			ID:         uuid.NewString(),
			AccountID:  email,
			ProviderID: "credentials",
			UserID:     userID,
			Password:   &hashedPassword,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := s.repo.CreateAccount(txCtx, account); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, ErrInternalServer
	}

	return user, nil
}

func (s *AuthServiceImpl) Login(ctx context.Context, email, password string) (*models.User, *security.IssuedTokens, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, ErrInternalServer
	}

	account, err := s.repo.GetAccountByUserIDAndProvider(ctx, user.ID, "credentials")
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, ErrInternalServer
	}

	if account.Password == nil {
		return nil, nil, ErrInvalidCredentials
	}

	match, err := security.VerifyPassword(password, *account.Password)
	if err != nil || !match {
		return nil, nil, ErrInvalidCredentials
	}

	tokenConfig := security.TokenConfig{
		Secret:     []byte(s.jwtCfg.Secret),
		AccessTTL:  time.Duration(s.jwtCfg.AccessTTL) * time.Second,
		RefreshTTL: time.Duration(s.jwtCfg.RefreshTTL) * time.Second,
	}

	// Fetch dynamic user permissions from GORM tables
	perms, err := s.repo.GetUserPermissions(ctx, user.ID)
	if err != nil {
		return nil, nil, ErrInternalServer
	}

	issued, err := security.IssueTokens(tokenConfig, user.ID, user.ID, []string{"password"}, perms)
	if err != nil {
		return nil, nil, ErrInternalServer
	}

	// Store Session record in DB
	now := time.Now()
	session := &models.Session{
		ID:        issued.JTI,
		ExpiresAt: now.Add(tokenConfig.RefreshTTL),
		Token:     issued.RefreshToken,
		UserID:    user.ID,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.repo.CreateSession(ctx, session); err != nil {
		return nil, nil, ErrInternalServer
	}

	return user, issued, nil
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
	err := s.repo.DeleteSession(ctx, sessionID)
	if err != nil {
		return ErrInternalServer
	}
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
