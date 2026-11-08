package auth

import (
	"context"
	"time"

	"github.com/misbakhul29/backend-framework/pkg/db"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"gorm.io/gorm"
)

type AuthRepository interface {
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	GetAccountByUserIDAndProvider(ctx context.Context, userID string, providerID string) (*models.Account, error)
	CreateUser(ctx context.Context, user *models.User) error
	CreateAccount(ctx context.Context, account *models.Account) error
	CreateSession(ctx context.Context, session *models.Session) error
	DeleteSession(ctx context.Context, sessionID string) error
	GetUserPermissions(ctx context.Context, userID string) ([]string, error)
	UpdateUserRole(ctx context.Context, userID string, roleName string) error
	GetRoleByName(ctx context.Context, name string) (*models.Role, error)

	// Password and verification operations
	UpdateAccountPassword(ctx context.Context, accountID string, passwordHash string) error
	CreateVerification(ctx context.Context, v *models.Verification) error
	GetVerificationByValue(ctx context.Context, value string) (*models.Verification, error)
	DeleteVerification(ctx context.Context, id string) error
	DeleteVerificationsByIdentifier(ctx context.Context, identifier string) error
	RevokeUserSessions(ctx context.Context, userID string, exceptSessionID string) error

	// Refresh Token Rotation (RTR)
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error)
	CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error
	RevokeRefreshToken(ctx context.Context, tokenID string, replacedByTokenID *string) (bool, error)
	RevokeTokenFamily(ctx context.Context, familyID string) error
	RevokeSession(ctx context.Context, sessionID string) error
	RevokeFamilySessions(ctx context.Context, familyID string) error
	UpdateSessionTokenHash(ctx context.Context, sessionID string, tokenHash string) error

	// Session management
	GetActiveSessionsByUserID(ctx context.Context, userID string) ([]models.Session, error)
	RevokeSessionByID(ctx context.Context, sessionID, userID string) error
	RevokeSessionsByUserID(ctx context.Context, userID string, excludeSessionID string) (int64, error)
	UpdateSessionLastActive(ctx context.Context, sessionID string) error
}

type AuthRepositoryImpl struct {
	db *gorm.DB
}

func NewRepository(dbClient *gorm.DB) *AuthRepositoryImpl {
	return &AuthRepositoryImpl{db: dbClient}
}

func (r *AuthRepositoryImpl) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Where("email = ?", email).First(&user).Error
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepositoryImpl) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Where("id = ?", id).First(&user).Error
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepositoryImpl) GetAccountByUserIDAndProvider(ctx context.Context, userID string, providerID string) (*models.Account, error) {
	var account models.Account
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Where("user_id = ? AND provider_id = ?", userID, providerID).First(&account).Error
	})
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func (r *AuthRepositoryImpl) CreateUser(ctx context.Context, user *models.User) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Create(user).Error
	})
}

func (r *AuthRepositoryImpl) CreateAccount(ctx context.Context, account *models.Account) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Create(account).Error
	})
}

func (r *AuthRepositoryImpl) CreateSession(ctx context.Context, session *models.Session) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Create(session).Error
	})
}

func (r *AuthRepositoryImpl) DeleteSession(ctx context.Context, sessionID string) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Delete(&models.Session{}, "id = ?", sessionID).Error
	})
}

func (r *AuthRepositoryImpl) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	var permissions []string
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		var user models.User
		if err := tx.Preload("Roles.Permissions").Where("id = ?", userID).First(&user).Error; err != nil {
			return err
		}
		seen := make(map[string]bool)
		for _, role := range user.Roles {
			for _, perm := range role.Permissions {
				if !seen[perm.Code] {
					seen[perm.Code] = true
					permissions = append(permissions, perm.Code)
				}
			}
		}
		return nil
	})
	return permissions, err
}

func (r *AuthRepositoryImpl) UpdateUserRole(ctx context.Context, userID string, roleName string) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		var user models.User
		if err := tx.Where("id = ?", userID).First(&user).Error; err != nil {
			return err
		}
		var role models.Role
		if err := tx.Where("name = ?", roleName).First(&role).Error; err != nil {
			return err
		}
		return tx.Model(&user).Association("Roles").Replace([]models.Role{role})
	})
}

func (r *AuthRepositoryImpl) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	var role models.Role
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Where("name = ?", name).First(&role).Error
	})
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *AuthRepositoryImpl) UpdateAccountPassword(ctx context.Context, accountID string, passwordHash string) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Model(&models.Account{}).Where("id = ?", accountID).Update("password", passwordHash).Error
	})
}

func (r *AuthRepositoryImpl) CreateVerification(ctx context.Context, v *models.Verification) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Create(v).Error
	})
}

func (r *AuthRepositoryImpl) GetVerificationByValue(ctx context.Context, value string) (*models.Verification, error) {
	var v models.Verification
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Where("value = ?", value).First(&v).Error
	})
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (r *AuthRepositoryImpl) DeleteVerification(ctx context.Context, id string) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Delete(&models.Verification{}, "id = ?", id).Error
	})
}

func (r *AuthRepositoryImpl) DeleteVerificationsByIdentifier(ctx context.Context, identifier string) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Delete(&models.Verification{}, "identifier = ?", identifier).Error
	})
}

func (r *AuthRepositoryImpl) RevokeUserSessions(ctx context.Context, userID string, exceptSessionID string) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		sessionQuery := tx.Model(&models.Session{}).Where("user_id = ?", userID)
		if exceptSessionID != "" {
			sessionQuery = sessionQuery.Where("id != ?", exceptSessionID)
		}

		var sessionIDs []string
		if err := sessionQuery.Pluck("id", &sessionIDs).Error; err != nil {
			return err
		}

		if len(sessionIDs) > 0 {
			if err := tx.Model(&models.RefreshToken{}).Where("session_id IN ?", sessionIDs).Update("is_revoked", true).Error; err != nil {
				return err
			}
			if err := tx.Model(&models.Session{}).Where("id IN ?", sessionIDs).Update("is_revoked", true).Error; err != nil {
				return err
			}
		}

		return nil
	})
}

func (r *AuthRepositoryImpl) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Preload("Session").Where("token_hash = ?", tokenHash).First(&token).Error
	})
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (r *AuthRepositoryImpl) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Create(token).Error
	})
}

func (r *AuthRepositoryImpl) RevokeRefreshToken(ctx context.Context, tokenID string, replacedByTokenID *string) (bool, error) {
	var rowsAffected int64
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		updates := map[string]interface{}{"is_revoked": true}
		if replacedByTokenID != nil {
			updates["replaced_by_token_id"] = *replacedByTokenID
		}
		res := tx.Model(&models.RefreshToken{}).
			Where("id = ? AND is_revoked = ?", tokenID, false).
			Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		rowsAffected = res.RowsAffected
		return nil
	})
	return rowsAffected > 0, err
}

func (r *AuthRepositoryImpl) RevokeTokenFamily(ctx context.Context, familyID string) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Model(&models.RefreshToken{}).Where("family_id = ?", familyID).Update("is_revoked", true).Error
	})
}

func (r *AuthRepositoryImpl) RevokeSession(ctx context.Context, sessionID string) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		_ = tx.Model(&models.RefreshToken{}).Where("session_id = ?", sessionID).Update("is_revoked", true).Error
		return tx.Model(&models.Session{}).Where("id = ?", sessionID).Update("is_revoked", true).Error
	})
}

func (r *AuthRepositoryImpl) RevokeFamilySessions(ctx context.Context, familyID string) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Model(&models.Session{}).Where("family_id = ?", familyID).Update("is_revoked", true).Error
	})
}

func (r *AuthRepositoryImpl) UpdateSessionTokenHash(ctx context.Context, sessionID string, tokenHash string) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Model(&models.Session{}).Where("id = ?", sessionID).Updates(map[string]interface{}{
			"token_hash": tokenHash,
			"updated_at": time.Now(),
		}).Error
	})
}

func (r *AuthRepositoryImpl) GetActiveSessionsByUserID(ctx context.Context, userID string) ([]models.Session, error) {
	var sessions []models.Session
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Where("user_id = ? AND is_revoked = ? AND expires_at > ?", userID, false, time.Now()).
			Order("last_active_at DESC, created_at DESC").
			Find(&sessions).Error
	})
	return sessions, err
}

func (r *AuthRepositoryImpl) RevokeSessionByID(ctx context.Context, sessionID, userID string) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		var session models.Session
		if err := tx.Where("id = ? AND user_id = ? AND is_revoked = ?", sessionID, userID, false).First(&session).Error; err != nil {
			return err
		}

		_ = tx.Model(&models.RefreshToken{}).Where("session_id = ?", sessionID).Update("is_revoked", true).Error
		return tx.Model(&session).Update("is_revoked", true).Error
	})
}

func (r *AuthRepositoryImpl) RevokeSessionsByUserID(ctx context.Context, userID string, excludeSessionID string) (int64, error) {
	var count int64
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		query := tx.Model(&models.Session{}).Where("user_id = ? AND is_revoked = ?", userID, false)
		if excludeSessionID != "" {
			query = query.Where("id != ?", excludeSessionID)
		}

		var sessionIDs []string
		if err := query.Pluck("id", &sessionIDs).Error; err != nil {
			return err
		}

		if len(sessionIDs) == 0 {
			count = 0
			return nil
		}

		if err := tx.Model(&models.RefreshToken{}).Where("session_id IN ?", sessionIDs).Update("is_revoked", true).Error; err != nil {
			return err
		}

		res := tx.Model(&models.Session{}).Where("id IN ?", sessionIDs).Update("is_revoked", true)
		if res.Error != nil {
			return res.Error
		}
		count = res.RowsAffected
		return nil
	})
	return count, err
}

func (r *AuthRepositoryImpl) UpdateSessionLastActive(ctx context.Context, sessionID string) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Model(&models.Session{}).Where("id = ?", sessionID).Update("last_active_at", time.Now()).Error
	})
}
