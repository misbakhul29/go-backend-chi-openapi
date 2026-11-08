package models

import (
	"time"
)

const (
	RoleAdmin   = "ADMIN"
	RoleMember  = "MEMBER"
	DefaultRole = RoleMember
)

type User struct {
	ID            string          `gorm:"primaryKey;type:varchar(255)"`
	Name          string          `gorm:"type:varchar(255);not null"`
	Email         string          `gorm:"type:varchar(255);unique;not null"`
	EmailVerified bool            `gorm:"not null;default:false"`
	Image         *string         `gorm:"type:text"`
	MfaEnabled    bool            `gorm:"not null;default:false"`
	MfaSecret     *string         `gorm:"type:text"`
	IsActive      bool            `gorm:"not null;default:true"`
	LastLoginAt   *time.Time      `gorm:""`
	CreatedAt     time.Time       `gorm:"not null"`
	UpdatedAt     time.Time       `gorm:"not null"`
	Sessions      []Session       `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Accounts      []Account       `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Roles         []Role          `gorm:"many2many:user_roles;constraint:OnDelete:CASCADE"`
	BackupCodes   []MfaBackupCode `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

func (User) TableName() string {
	return "user"
}

type Role struct {
	ID          string       `gorm:"primaryKey;type:varchar(255)"`
	Name        string       `gorm:"type:varchar(255);unique;not null"`
	IsDefault   bool         `gorm:"not null;default:false"`
	CreatedAt   time.Time    `gorm:"not null"`
	UpdatedAt   time.Time    `gorm:"not null"`
	Permissions []Permission `gorm:"many2many:role_permissions;constraint:OnDelete:CASCADE"`
	Users       []User       `gorm:"many2many:user_roles;constraint:OnDelete:CASCADE"`
}

func (Role) TableName() string {
	return "role"
}

type Permission struct {
	ID        string    `gorm:"primaryKey;type:varchar(255)"`
	Code      string    `gorm:"type:varchar(255);unique;not null"`
	CreatedAt time.Time `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null"`
}

func (Permission) TableName() string {
	return "permission"
}

type Session struct {
	ID            string         `gorm:"primaryKey;type:varchar(255)"`
	ExpiresAt     time.Time      `gorm:"not null;index:idx_session_expires"`
	Token         string         `gorm:"type:varchar(255);default:''"`
	TokenHash     string         `gorm:"type:varchar(64);index:idx_session_token_hash"`
	FamilyID      string         `gorm:"type:varchar(255);index:idx_session_family_id"`
	IsRevoked     bool           `gorm:"not null;default:false;index:idx_session_revoked"`
	CreatedAt     time.Time      `gorm:"not null"`
	UpdatedAt     time.Time      `gorm:"not null"`
	LastActiveAt  *time.Time     `gorm:"index:idx_session_last_active"`
	IPAddress     *string        `gorm:"type:varchar(45)"`
	UserAgent     *string        `gorm:"type:text"`
	Device        *string        `gorm:"type:varchar(255)"`
	UserID        string         `gorm:"type:varchar(255);not null;index:idx_session_user_id"`
	User          User           `gorm:"foreignKey:UserID"`
	RefreshTokens []RefreshToken `gorm:"foreignKey:SessionID;constraint:OnDelete:CASCADE"`
}

func (Session) TableName() string {
	return "session"
}

type RefreshToken struct {
	ID                string    `gorm:"primaryKey;type:varchar(255)"`
	SessionID         string    `gorm:"type:varchar(255);not null;index:idx_refresh_token_session_id"`
	Session           Session   `gorm:"foreignKey:SessionID"`
	FamilyID          string    `gorm:"type:varchar(255);not null;index:idx_refresh_token_family_id"`
	TokenHash         string    `gorm:"type:varchar(64);uniqueIndex:uq_refresh_token_hash;not null"`
	IsRevoked         bool      `gorm:"not null;default:false;index:idx_refresh_token_revoked"`
	ReplacedByTokenID *string   `gorm:"type:varchar(255)"`
	ExpiresAt         time.Time `gorm:"not null;index:idx_refresh_token_expires"`
	CreatedAt         time.Time `gorm:"not null"`
}

func (RefreshToken) TableName() string {
	return "refresh_token"
}

type MfaBackupCode struct {
	ID        string     `gorm:"primaryKey;type:varchar(255)"`
	UserID    string     `gorm:"type:varchar(255);not null;index:idx_mfa_backup_code_user_id;index:idx_mfa_backup_code_user_used,priority:1"`
	User      User       `gorm:"foreignKey:UserID"`
	CodeHash  string     `gorm:"type:varchar(64);not null;index:idx_mfa_backup_code_hash"`
	IsUsed    bool       `gorm:"not null;default:false;index:idx_mfa_backup_code_user_used,priority:2"`
	UsedAt    *time.Time `gorm:""`
	CreatedAt time.Time  `gorm:"not null"`
}

func (MfaBackupCode) TableName() string {
	return "mfa_backup_code"
}

type AuditLog struct {
	ID        string    `gorm:"primaryKey;type:varchar(255)"`
	Timestamp time.Time `gorm:"not null;index:idx_audit_log_timestamp"`
	EventType string    `gorm:"type:varchar(100);not null;index:idx_audit_log_event_type"`
	UserID    *string   `gorm:"type:varchar(255);index:idx_audit_log_user_id"`
	TenantID  *string   `gorm:"type:varchar(255);index:idx_audit_log_tenant_id"`
	IPAddress *string   `gorm:"type:varchar(45)"`
	UserAgent *string   `gorm:"type:text"`
	Status    string    `gorm:"type:varchar(50);not null"`
	Metadata  *string   `gorm:"type:text"`
	CreatedAt time.Time `gorm:"not null"`
}

func (AuditLog) TableName() string {
	return "audit_log"
}

type Account struct {
	ID                    string     `gorm:"primaryKey;type:varchar(255)"`
	AccountID             string     `gorm:"type:varchar(255);not null"`
	ProviderID            string     `gorm:"type:varchar(255);not null"`
	UserID                string     `gorm:"type:varchar(255);not null;index:idx_account_user_id"`
	User                  User       `gorm:"foreignKey:UserID"`
	AccessToken           *string    `gorm:"type:text"`
	RefreshToken          *string    `gorm:"type:text"`
	IDToken               *string    `gorm:"type:text"`
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scope                 *string    `gorm:"type:text"`
	Password              *string    `gorm:"type:varchar(255)"`
	CreatedAt             time.Time  `gorm:"not null"`
	UpdatedAt             time.Time  `gorm:"not null"`
}

func (Account) TableName() string {
	return "account"
}

type Verification struct {
	ID         string     `gorm:"primaryKey;type:varchar(255)"`
	Identifier string     `gorm:"type:varchar(255);not null;index:idx_verification_id_val,priority:1"`
	Value      string     `gorm:"type:varchar(255);not null;index:idx_verification_id_val,priority:2"`
	ExpiresAt  time.Time  `gorm:"not null;index:idx_verification_expires"`
	CreatedAt  *time.Time
	UpdatedAt  *time.Time
}

func (Verification) TableName() string {
	return "verification"
}
