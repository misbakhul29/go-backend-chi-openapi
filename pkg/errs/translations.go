package errs

// Translations dictionary: Key -> Language -> Message string
var translations = map[string]map[Language]string{
	// ── Common & System ────────────────────────────────────────────────────────
	string(ErrCodeInternalError): {
		ID: "Terjadi kesalahan internal, silakan coba lagi",
		EN: "An internal server error occurred, please try again",
	},
	string(ErrCodeBadRequest): {
		ID: "Format permintaan tidak valid",
		EN: "Invalid request payload",
	},
	string(ErrCodeUnauthorized): {
		ID: "Akses ditolak, token tidak valid atau kadaluarsa",
		EN: "Unauthorized access, token invalid or expired",
	},
	string(ErrCodeForbidden): {
		ID: "Anda tidak memiliki akses ke sumber daya ini",
		EN: "You do not have permission to access this resource",
	},
	string(ErrCodeModuleDisabled): {
		ID: "Modul ini dinonaktifkan untuk perusahaan Anda",
		EN: "This module is disabled for your tenant",
	},
	string(ErrCodeTenantSuspended): {
		ID: "Akses perusahaan ditangguhkan",
		EN: "Tenant access is suspended",
	},
	string(ErrCodeMfaRequired): {
		ID: "MFA diperlukan untuk melanjutkan",
		EN: "MFA is required to proceed",
	},
	string(ErrCodeNotFound): {
		ID: "Data tidak ditemukan",
		EN: "Resource not found",
	},
	string(ErrCodeConflict): {
		ID: "Konflik akses data terdeteksi, silakan coba lagi",
		EN: "Data access conflict detected, please try again",
	},
	string(ErrCodeValidation): {
		ID: "Validasi data gagal",
		EN: "Data validation failed",
	},
	string(ErrCodeRequestTimeout): {
		ID: "Permintaan memakan waktu terlalu lama, silakan coba lagi",
		EN: "Request timed out, please try again",
	},
	string(ErrCodeServiceUnavailable): {
		ID: "Layanan sedang sibuk, silakan coba beberapa saat lagi",
		EN: "Service is temporarily busy, please try again later",
	},
	string(ErrCodeRateLimitExceeded): {
		ID: "Terlalu banyak permintaan, silakan coba beberapa saat lagi",
		EN: "Too many requests, please try again later",
	},

	// ── Organization Module ───────────────────────────────────────────────────
	string(ErrCodeCycleDetected): {
		ID: "Siklus hierarki terdeteksi, tidak dapat menetapkan induk ini",
		EN: "Hierarchy cycle detected, cannot set this parent",
	},
	string(ErrCodeResourceInUse): {
		ID: "Data tidak dapat dihapus karena masih digunakan oleh referensi aktif",
		EN: "Resource cannot be deleted because active references exist",
	},
	string(ErrCodeInvalidParent): {
		ID: "Data induk tidak valid, tidak aktif, atau tidak ditemukan",
		EN: "Parent resource is invalid, inactive, or not found",
	},
	string(ErrCodeInvalidJSON): {
		ID: "Format JSON payload tidak valid",
		EN: "Invalid JSON payload format",
	},
	string(ErrCodeOverlappingSchedule): {
		ID: "Jadwal kerja tumpang tindih dengan periode yang sudah ada",
		EN: "Work schedule overlaps with an existing valid period",
	},
	string(ErrCodeInvalidCoordinates): {
		ID: "Koordinat latitude (-90 s/d 90) atau longitude (-180 s/d 180) tidak valid",
		EN: "Invalid latitude (-90 to 90) or longitude (-180 to 180) coordinates",
	},
	string(ErrCodeInvalidRadius): {
		ID: "Radius geofence harus berada di antara 50 sampai 5000 meter",
		EN: "Geofence radius must be between 50 and 5000 meters",
	},
	string(ErrCodeCalendarNotFound): {
		ID: "Kalender libur tidak ditemukan",
		EN: "Holiday calendar not found",
	},
	string(ErrCodeInvalidCSVFormat): {
		ID: "Format CSV tidak valid, pastikan header: date,name,type,deduct_leave",
		EN: "Invalid CSV format, ensure header: date,name,type,deduct_leave",
	},

	// ── Auth & Identity ────────────────────────────────────────────────────────
	string(ErrCodeAccountLocked): {
		ID: "Akun terkunci sementara karena terlalu banyak percobaan login yang gagal",
		EN: "Account is temporarily locked due to too many failed login attempts",
	},
	string(ErrCodeLegacyPasswordResetRequired): {
		ID: "Reset kata sandi diperlukan untuk akun lama Anda",
		EN: "Password reset is required for your legacy account",
	},
	string(ErrCodeMfaEnrollRequired): {
		ID: "Pendaftaran MFA wajib dilakukan untuk peran Anda",
		EN: "MFA enrollment is required for your role",
	},
	string(ErrCodeInvalidCredentials): {
		ID: "Email atau kata sandi tidak cocok",
		EN: "Invalid email or password",
	},
	string(ErrCodeTokenReuseDetected): {
		ID: "Penggunaan ulang refresh token terdeteksi. Semua sesi dicabut.",
		EN: "Refresh token reuse detected. All active sessions have been revoked.",
	},
	string(ErrCodeDeviceRevoked): {
		ID: "Akses perangkat ini telah dicabut",
		EN: "This device access session has been revoked",
	},
	string(ErrCodeInvalidMfaTicket): {
		ID: "Tiket MFA tidak valid atau telah kadaluarsa",
		EN: "Invalid or expired MFA ticket",
	},
	string(ErrCodeInvalidMfaCode): {
		ID: "Kode MFA atau kode cadangan tidak valid",
		EN: "Invalid MFA code or backup code",
	},
	string(ErrCodeMfaSetupFailed): {
		ID: "Gagal menyiapkan MFA",
		EN: "Failed to setup MFA",
	},
	string(ErrCodeMfaEnableFailed): {
		ID: "Gagal mengaktifkan MFA",
		EN: "Failed to enable MFA",
	},
	string(ErrCodeMfaVerifyFailed): {
		ID: "Gagal memverifikasi MFA",
		EN: "Failed to verify MFA",
	},
	string(ErrCodeMfaDisableFailed): {
		ID: "Gagal menonaktifkan MFA",
		EN: "Failed to disable MFA",
	},
	string(ErrCodeForgotPasswordFailed): {
		ID: "Gagal memproses instruksi reset kata sandi",
		EN: "Failed to process forgot password request",
	},
	string(ErrCodeResetPasswordFailed): {
		ID: "Gagal mereset kata sandi",
		EN: "Failed to reset password",
	},
	string(ErrCodeChangePasswordFailed): {
		ID: "Gagal mengubah kata sandi",
		EN: "Failed to change password",
	},
	string(ErrCodeRevokeDeviceFailed): {
		ID: "Gagal mencabut akses perangkat",
		EN: "Failed to revoke device session",
	},
	string(ErrCodeInvalidRefreshToken): {
		ID: "Refresh token tidak valid atau kedaluwarsa",
		EN: "Refresh token is invalid or expired",
	},
	string(ErrCodeInvalidToken): {
		ID: "Token tidak valid atau kedaluwarsa",
		EN: "Token is invalid or expired",
	},

	// ── Database Integrity Constraints ─────────────────────────────────────────
	string(ErrCodeDbUsersEmailKey): {
		ID: "Email sudah terdaftar",
		EN: "Email address is already registered",
	},
	string(ErrCodeDbUsersTenantIdEmailKey): {
		ID: "Email sudah terdaftar di tenant ini",
		EN: "Email address is already registered in this tenant",
	},
	string(ErrCodeDbUserDevicesUserIdDeviceCodeKey): {
		ID: "Perangkat sudah terdaftar",
		EN: "Device is already registered",
	},
	string(ErrCodeDbRefreshTokensTokenHashKey): {
		ID: "Token sudah digunakan",
		EN: "Token has already been used",
	},
	string(ErrCodeDbTenantsSlugKey): {
		ID: "Perusahaan dengan nama yang sama sudah terdaftar",
		EN: "Company with the same name is already registered",
	},
	string(ErrCodeDbTenantsDomainKey): {
		ID: "Domain sudah digunakan",
		EN: "Domain is already in use",
	},
	string(ErrCodeDbDepartmentsTenantIdCodeKey): {
		ID: "Kode departemen sudah digunakan",
		EN: "Department code is already in use",
	},
	string(ErrCodeDbLocationsTenantIdCodeKey): {
		ID: "Kode lokasi sudah digunakan",
		EN: "Location code is already in use",
	},
	string(ErrCodeDbPositionsTenantIdCodeKey): {
		ID: "Kode posisi sudah digunakan",
		EN: "Position code is already in use",
	},
	string(ErrCodeDbJobsTenantIdCodeKey): {
		ID: "Kode jabatan sudah digunakan",
		EN: "Job code is already in use",
	},
	string(ErrCodeDbLegalEntitiesTenantIdCodeKey): {
		ID: "Kode entitas legal sudah digunakan",
		EN: "Legal entity code is already in use",
	},
	string(ErrCodeDbCostCentersTenantIdCodeKey): {
		ID: "Kode cost center sudah digunakan",
		EN: "Cost center code is already in use",
	},
	string(ErrCodeDbEmployeesTenantIdEmpNumKey): {
		ID: "Nomor karyawan sudah digunakan",
		EN: "Employee ID number is already in use",
	},
	string(ErrCodeDbEmployeesTenantIdNikKey): {
		ID: "NIK sudah terdaftar",
		EN: "National ID (NIK) is already registered",
	},
	string(ErrCodeDbLeaveTypesTenantIdCodeKey): {
		ID: "Kode jenis cuti sudah digunakan",
		EN: "Leave type code is already in use",
	},
	string(ErrCodeDbSalaryComponentsTenantIdCodeKey): {
		ID: "Kode komponen gaji sudah digunakan",
		EN: "Salary component code is already in use",
	},

	// ── Foreign Keys ───────────────────────────────────────────────────────────
	string(ErrCodeFkEmployeesDeptId): {
		ID: "Departemen tidak ditemukan",
		EN: "Department not found",
	},
	string(ErrCodeFkEmployeesPosId): {
		ID: "Posisi tidak ditemukan",
		EN: "Position not found",
	},
	string(ErrCodeFkEmployeesLocId): {
		ID: "Lokasi tidak ditemukan",
		EN: "Location not found",
	},
	string(ErrCodeFkEmployeesJobId): {
		ID: "Jabatan tidak ditemukan",
		EN: "Job not found",
	},
	string(ErrCodeFkEmployeesReportingTo): {
		ID: "Atasan tidak ditemukan",
		EN: "Reporting manager not found",
	},
	string(ErrCodeFkUserRolesRoleId): {
		ID: "Role tidak ditemukan",
		EN: "Role not found",
	},
	string(ErrCodeFkUserRolesUserId): {
		ID: "User tidak ditemukan",
		EN: "User not found",
	},
	string(ErrCodeFkLeaveRequestsType): {
		ID: "Jenis cuti tidak ditemukan",
		EN: "Leave type not found",
	},

	// ── Columns ────────────────────────────────────────────────────────────────
	"col_email":           {ID: "Email", EN: "Email"},
	"col_full_name":       {ID: "Nama lengkap", EN: "Full name"},
	"col_phone":           {ID: "Nomor telepon", EN: "Phone number"},
	"col_employee_number": {ID: "Nomor karyawan", EN: "Employee number"},
	"col_nik":             {ID: "NIK", EN: "National ID (NIK)"},
	"col_department_id":   {ID: "Departemen", EN: "Department"},
	"col_position_id":     {ID: "Posisi", EN: "Position"},
	"col_location_id":     {ID: "Lokasi", EN: "Location"},
	"col_job_id":          {ID: "Jabatan", EN: "Job title"},
	"col_tenant_id":       {ID: "Tenant", EN: "Tenant"},
	"col_user_id":         {ID: "User", EN: "User"},
	"col_status":          {ID: "Status", EN: "Status"},
	"col_start_date":      {ID: "Tanggal mulai", EN: "Start date"},
	"col_end_date":        {ID: "Tanggal selesai", EN: "End date"},
	"col_effective_date":  {ID: "Tanggal efektif", EN: "Effective date"},
	"col_code":            {ID: "Kode", EN: "Code"},
	"col_name":            {ID: "Nama", EN: "Name"},
	"col_password_hash":   {ID: "Password", EN: "Password"},
	"col_amount":          {ID: "Jumlah", EN: "Amount"},
	"col_currency":        {ID: "Mata uang", EN: "Currency"},

	// ── Generic Fallbacks ──────────────────────────────────────────────────────
	string(ErrCodeExclusionViolation): {
		ID: "Data bertumpang tindih dengan data yang sudah ada",
		EN: "Data overlaps with an existing record",
	},
	string(ErrCodeStringTooLong): {
		ID: "Panjang data melebihi batas yang diizinkan",
		EN: "Data length exceeds maximum allowed limit",
	},
	string(ErrCodeNumericOutOfRange): {
		ID: "Nilai numerik di luar rentang yang diizinkan",
		EN: "Numeric value is out of allowed range",
	},
	string(ErrCodeInvalidFormat): {
		ID: "Format data tidak valid",
		EN: "Invalid data format",
	},
	string(ErrCodeDivisionByZero): {
		ID: "Pembagian dengan nol terdeteksi",
		EN: "Division by zero detected",
	},
	string(ErrCodeDatetimeOverflow): {
		ID: "Nilai tanggal/waktu di luar rentang yang diizinkan",
		EN: "Date/time value is out of allowed range",
	},
	string(ErrCodeDeadlock): {
		ID: "Konflik akses data terdeteksi, silakan coba lagi",
		EN: "Data access deadlock detected, please try again",
	},
	string(ErrCodeFkReferenced): {
		ID: "Data tidak dapat dihapus karena masih digunakan oleh data lain",
		EN: "Data cannot be deleted because it is referenced by other records",
	},
	string(ErrCodeFkNotFound): {
		ID: "Data referensi tidak ditemukan",
		EN: "Referenced data not found",
	},
	string(ErrCodeNotNullViolation): {
		ID: "Data wajib diisi tidak boleh kosong",
		EN: "Required field cannot be empty",
	},
	string(ErrCodeCheckViolation): {
		ID: "Data tidak memenuhi aturan validasi",
		EN: "Data does not satisfy validation check constraint",
	},
	string(ErrCodeDuplicateGeneric): {
		ID: "Data sudah ada, tidak dapat membuat duplikat",
		EN: "Record already exists, duplicate is not allowed",
	},
	string(ErrCodeDatabaseError): {
		ID: "Terjadi kesalahan database, silakan coba lagi",
		EN: "A database error occurred, please try again",
	},

	// ── Messages ──────────────────────────────────────────────────────────────
	string(MsgLoggedOutSuccess): {
		ID: "Berhasil keluar",
		EN: "Logged out successfully",
	},
	string(MsgLoggedOutAllSuccess): {
		ID: "Berhasil keluar dari semua perangkat",
		EN: "Successfully logged out from all devices",
	},
	string(MsgForgotPasswordSent): {
		ID: "Jika email Anda terdaftar, Anda akan menerima instruksi pengaturan ulang kata sandi.",
		EN: "If your email is registered, you will receive password reset instructions.",
	},
	string(MsgPasswordResetSuccess): {
		ID: "Kata sandi berhasil diubah, silahkan login kembali.",
		EN: "Password has been changed successfully, please login again.",
	},
	string(MsgTenantRegisterSuccess): {
		ID: "Registrasi perusahaan berhasil.",
		EN: "Company registration successful.",
	},
}
