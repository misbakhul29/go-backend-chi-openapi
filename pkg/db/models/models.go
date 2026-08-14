package models

import (
	"time"
)

type User struct {
	ID            string    `gorm:"primaryKey;type:varchar(255)"`
	Name          string    `gorm:"type:varchar(255);not null"`
	Email         string    `gorm:"type:varchar(255);unique;not null"`
	EmailVerified bool      `gorm:"not null"`
	Image         *string   `gorm:"type:text"`
	CreatedAt     time.Time `gorm:"not null"`
	UpdatedAt     time.Time `gorm:"not null"`
	Sessions      []Session `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Accounts      []Account `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

func (User) TableName() string {
	return "user"
}

type Session struct {
	ID        string    `gorm:"primaryKey;type:varchar(255)"`
	ExpiresAt time.Time `gorm:"not null"`
	Token     string    `gorm:"type:varchar(255);unique;not null"`
	CreatedAt time.Time `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null"`
	IPAddress *string   `gorm:"type:varchar(45)"`
	UserAgent *string   `gorm:"type:text"`
	UserID    string    `gorm:"type:varchar(255);not null"`
	User      User      `gorm:"foreignKey:UserID"`
}

func (Session) TableName() string {
	return "session"
}

type Account struct {
	ID                    string     `gorm:"primaryKey;type:varchar(255)"`
	AccountID             string     `gorm:"type:varchar(255);not null"`
	ProviderID            string     `gorm:"type:varchar(255);not null"`
	UserID                string     `gorm:"type:varchar(255);not null"`
	User                  User       `gorm:"foreignKey:UserID"`
	AccessToken           *string    `gorm:"type:text"`
	RefreshToken          *string    `gorm:"type:text"`
	IDToken               *string    `gorm:"type:text"`
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scope                 *string    `gorm:"type:text"`
	Password              *string    `gorm:"type:varchar(255)"` // local auth password hash
	CreatedAt             time.Time  `gorm:"not null"`
	UpdatedAt             time.Time  `gorm:"not null"`
}

func (Account) TableName() string {
	return "account"
}

type Verification struct {
	ID         string     `gorm:"primaryKey;type:varchar(255)"`
	Identifier string     `gorm:"type:varchar(255);not null"`
	Value      string     `gorm:"type:varchar(255);not null"`
	ExpiresAt  time.Time  `gorm:"not null"`
	CreatedAt  *time.Time
	UpdatedAt  *time.Time
}

func (Verification) TableName() string {
	return "verification"
}
