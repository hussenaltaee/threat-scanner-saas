-- Migration 002: Seed reference and default configuration data.

INSERT INTO roles (name, slug, description)
SELECT 'admin', 'admin', 'System administrator'
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE slug = 'admin');

INSERT INTO roles (name, slug, description)
SELECT 'clinic_owner', 'clinic_owner', 'Clinic owner or manager'
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE slug = 'clinic_owner');

INSERT INTO roles (name, slug, description)
SELECT 'doctor', 'doctor', 'Doctor or specialist'
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE slug = 'doctor');

INSERT INTO roles (name, slug, description)
SELECT 'patient', 'patient', 'Patient or customer'
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE slug = 'patient');

INSERT INTO roles (name, slug, description)
SELECT 'support', 'support', 'Support staff'
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE slug = 'support');

INSERT INTO admin_settings (key_name, key_value, description)
SELECT 'app_name', 'ClinicFlow', 'Display name of the SaaS application'
WHERE NOT EXISTS (SELECT 1 FROM admin_settings WHERE key_name = 'app_name');

INSERT INTO admin_settings (key_name, key_value, description)
SELECT 'default_booking_status', 'pending', 'Default status used when a booking is created'
WHERE NOT EXISTS (SELECT 1 FROM admin_settings WHERE key_name = 'default_booking_status');

INSERT INTO admin_settings (key_name, key_value, description)
SELECT 'default_notification_channel', 'email', 'Default notification channel'
WHERE NOT EXISTS (SELECT 1 FROM admin_settings WHERE key_name = 'default_notification_channel');
