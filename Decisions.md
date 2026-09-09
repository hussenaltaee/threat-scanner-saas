# Decisions and Architecture Rules

## 1. Principles

1. The database schema is the source of truth. The UI is only a view layer.
2. Never add columns or tables because a screen seems to need them. Add them only because a business fact exists.
3. Every table must have a clear business purpose and a relationship to another table.
4. No orphan data. If a record references another table, the relationship must be explicit and enforced.
5. No duplicate lists or parallel copies of the same fact.
6. No ad-hoc fields created from a single session or one-off idea. Use migration numbering and business review.
7. If a detail is not confirmed, it must not be invented. The AI must write only what is documented here.
8. Migrations must be ordered from oldest to newest and must be reversible or at least explainable.
9. All API endpoints must map to a domain action and a corresponding data model.

## 2. Domain Decision

This project is modeled as a booking and subscription SaaS platform with the following business entities:

- User
- Role
- Clinic
- Doctor / specialist
- Service
- Booking / appointment
- Subscription / plan
- Payment / invoice
- Message / chat thread
- Notification
- Audit log
- Support ticket
- Admin settings

The project must not create database tables based on a page layout, screen names, or UI labels.

## 3. Entity Rules

### User
- Represents a human account.
- May be admin, clinic owner, doctor, patient, or support.
- Has one account, one email/phone identity, and multiple roles possible if needed.
- Must not duplicate profile data across unrelated tables.

### Role
- Defines permissions and access boundaries.
- Must map to authorization rules.
- Not a UI-only concept.

### Clinic
- Represents a branch, center, or facility.
- One clinic may have many doctors and many services.
- Has owner/manager reference.

### Doctor
- Represents a professional working in a clinic.
- Belongs to one clinic or many clinics based on the business model.
- Has schedule, availability, and service assignment.

### Service
- Represents a medical or business service offered by a clinic.
- Linked to a clinic and optionally to a doctor.
- Has price, duration, category, and status.

### Booking
- Represents a customer appointment.
- Links patient, clinic, doctor/service, time slot, and status.
- One booking belongs to exactly one patient and one service at a minimum.

### Subscription
- Represents a recurring service or membership.
- May be attached to a clinic, user, or package.
- Must be separate from bookings because it is a recurring commercial contract, not a single appointment.

### Payment / Invoice
- Represents financial records.
- A booking may generate an invoice.
- A subscription may generate a recurring invoice.
- Payment data must be linked to its source object, not stored as loose text.

### Message / Conversation
- Represents communication between users, staff, and patients.
- Linked to a user and possibly to a booking or clinic.
- Must be tied to a real conversation thread, not stored as free-floating notes.

### Notification
- Represents alerts and reminders.
- Generated from booking, payment, subscription, or message events.

### Audit Log
- Records who changed what, when, and why.
- Must capture critical system actions.

### Support Ticket
- Represents customer or clinic support requests.
- May reference a user, clinic, or booking.

### Admin Settings
- Holds global configuration values.
- Must be centralized and versioned.

## 4. Data Integrity Rules

- A booking cannot exist without a patient and a service.
- A clinic cannot have a doctor without a clinic record.
- A subscription cannot be created without a valid owner and plan.
- A message must belong to a conversation and user.
- Payment must reference a source record, not just a raw amount.
- Audit logs cannot be deleted casually.

## 5. API and Backend Rules

- Each endpoint must map to one domain action.
- Each controller must call a service layer.
- Each service layer must operate on repository/database logic only.
- The backend must validate input and ensure FK relations.
- The frontend must never define the database schema.

## 6. Migration Rules

- Every change to the model must be added as a numbered migration.
- Migrations are ordered strictly by number.
- Do not create a new migration if a previous one is already responsible for the same table.
- No hidden columns, no stale tables, no duplicate state.
- Before creating a migration, confirm whether the target table already exists in the model.

## 7. AI Working Rule

The AI agent must follow this file as the contractual design source.

The AI must:
- read this file before generating code
- not invent business rules not listed here
- not create extra tables just to fill blank UI gaps
- not rename entities arbitrarily
- not create fields from assumptions
- not write code that contradicts these decisions

The AI may suggest improvements only if the change is first added to this file and then implemented through a migration.

## 8. Example of Correct vs Incorrect

Correct:
- Add a booking table linked to patient, clinic, service, and status.

Incorrect:
- Create a table called "booking_page" because the page shows booking form fields.
- Add "customer_phone" in multiple tables because multiple screens display it.
- Keep a duplicate admin_settings_copy table because it looks convenient.

## 9. Required Deliverables for the Project

1. Decisions.md
2. Project-Map-Tree.md
3. Database migration files in numbered order
4. Backend API routes mapped to entity actions
5. Frontend integration one page to one API contract
6. Cross-check that all tables are linked and no dead tables remain

## 10. Final Rule

If the AI agent starts creating tables based on screen wireframes instead of entity relations, it is violating the project architecture. The correct flow is:

Entity model -> migration -> backend -> API -> frontend

Not:

Screen -> duplicate table -> ad hoc columns -> backend patch later
