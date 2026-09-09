# Project Map Tree

## 1. Project Goal

This project must be organized around a business domain model, not around page names. The project map exists so the AI can find each component and understand how the system connects.

## 2. High-Level Tree

```text
project-root/
├── Decisions.md
├── Project-Map-Tree.md
├── README.md
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── routes/
│   │   │   │   ├── auth.py
│   │   │   │   ├── users.py
│   │   │   │   ├── clinics.py
│   │   │   │   ├── doctors.py
│   │   │   │   ├── services.py
│   │   │   │   ├── bookings.py
│   │   │   │   ├── subscriptions.py
│   │   │   │   ├── payments.py
│   │   │   │   ├── messages.py
│   │   │   │   ├── notifications.py
│   │   │   │   ├── support.py
│   │   │   │   └── admin.py
│   │   ├── core/
│   │   │   ├── config.py
│   │   │   ├── security.py
│   │   │   ├── auth.py
│   │   │   └── errors.py
│   │   ├── db/
│   │   │   ├── base.py
│   │   │   ├── session.py
│   │   │   ├── models/
│   │   │   │   ├── user.py
│   │   │   │   ├── clinic.py
│   │   │   │   ├── doctor.py
│   │   │   │   ├── service.py
│   │   │   │   ├── booking.py
│   │   │   │   ├── subscription.py
│   │   │   │   ├── payment.py
│   │   │   │   ├── message.py
│   │   │   │   ├── notification.py
│   │   │   │   ├── audit_log.py
│   │   │   │   └── support_ticket.py
│   │   │   ├── repositories/
│   │   │   │   ├── user_repository.py
│   │   │   │   ├── clinic_repository.py
│   │   │   │   ├── booking_repository.py
│   │   │   │   └── subscription_repository.py
│   │   │   └── migrations/
│   │   │       ├── 001_init_core_schema.sql
│   │   │       ├── 002_add_booking_relations.sql
│   │   │       ├── 003_add_subscription_and_invoice.sql
│   │   │       └── 004_add_notifications_and_audit.sql
│   │   ├── schemas/
│   │   │   ├── user.py
│   │   │   ├── clinic.py
│   │   │   ├── booking.py
│   │   │   ├── service.py
│   │   │   ├── subscription.py
│   │   │   └── message.py
│   │   ├── services/
│   │   │   ├── user_service.py
│   │   │   ├── clinic_service.py
│   │   │   ├── booking_service.py
│   │   │   ├── subscription_service.py
│   │   │   └── notification_service.py
│   │   └── main.py
│   ├── tests/
│   │   ├── test_auth.py
│   │   ├── test_bookings.py
│   │   ├── test_subscriptions.py
│   │   └── test_migrations.py
│   └── requirements.txt
├── frontend/
│   ├── assets/
│   ├── pages/
│   │   ├── auth/
│   │   │   ├── login.html
│   │   │   └── register.html
│   │   ├── dashboard/
│   │   │   ├── index.html
│   │   │   ├── bookings.html
│   │   │   ├── subscriptions.html
│   │   │   └── messages.html
│   │   └── admin/
│   │       └── settings.html
│   ├── js/
│   │   ├── api.js
│   │   ├── auth.js
│   │   ├── bookings.js
│   │   └── subscriptions.js
│   ├── styles/
│   └── index.html
└── docs/
    └── api-contracts/
```

## 3. Relationship Map

```text
User
 ├── has one or many Role
 ├── owns one or many Clinic
 ├── may be Doctor
 ├── makes many Booking
 ├── has many Notification
 ├── may have many Subscription
 └── may have many Message

Clinic
 ├── has many Doctor
 ├── offers many Service
 ├── hosts many Booking
 ├── has many Subscription
 └── has many SupportTicket

Doctor
 ├── belongs to Clinic
 ├── provides many Service
 └── manages many Booking

Service
 ├── belongs to Clinic
 ├── may be booked in many Booking
 └── may be linked to a Doctor

Booking
 ├── belongs to User (patient)
 ├── belongs to Clinic
 ├── belongs to Doctor
 ├── belongs to Service
 ├── may generate one Invoice
 ├── may create notifications
 └── may create messages or follow-up records

Subscription
 ├── belongs to User or Clinic
 ├── may be tied to a plan/package
 ├── generates recurring Payment / Invoice
 └── may create admin notifications

Payment / Invoice
 ├── belongs to Booking or Subscription
 ├── belongs to User
 └── updates accounting status

Message
 ├── belongs to Conversation / Thread
 ├── belongs to User
 ├── may relate to Booking
 └── may relate to Clinic

Notification
 ├── belongs to User
 ├── may relate to Booking, Subscription, or Payment
 └── may be created by system events

AuditLog
 ├── belongs to User (actor)
 ├── may relate to Booking, Clinic, Subscription, Payment
 └── records critical change history

SupportTicket
 ├── belongs to User
 ├── belongs to Clinic
 ├── may relate to Booking
 └── may create a notification
```

## 4. Connection Rules

- Every business record must point to its owner or parent.
- UI pages must never be used as the source for data schema.
- Frontend flows must be built after the entity and relation design is approved.
- A migration must be added whenever a relation changes.

## 5. AI Usage Rule

The AI must read this map before generating code. It must not invent a table without connecting it to an existing domain entity. It must also ensure each endpoint, service, schema, and database object match the map.

## 6. Build Order

1. Define entities and relations
2. Write migrations
3. Build database models
4. Build repositories
5. Build services
6. Build API routes
7. Connect frontend pages to API contracts
8. Validate with tests and migration checks
