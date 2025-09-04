# safe_migration_script.py
"""
Safe migration script for adding patient/doctor linking to meetings table.
This script handles existing data properly to avoid NOT NULL constraint violations.
"""

from app import create_app, db
from app.models.user_models import User, Role
from sqlalchemy import text
from app.utils.encryption_util import encryptor
import json

def create_default_entities():
    """Create default doctor and patient for orphaned meetings."""
    app = create_app()
    
    with app.app_context():
        print("Creating default entities for orphaned meetings...")
        
        # Check if default entities already exist
        default_doctor = User.query.filter_by(username_hash=User.create_hash("default_doctor")).first()
        default_patient = User.query.filter_by(username_hash=User.create_hash("default_patient")).first()
        
        if default_doctor and default_patient:
            print("Default entities already exist")
            return default_doctor.id, default_patient.id
        
        # Get roles
        doctor_role = Role.query.filter_by(name='doctor').first()
        patient_role = Role.query.filter_by(name='patient').first()
        
        if not doctor_role or not patient_role:
            print("ERROR: Doctor or Patient roles not found in database")
            return None, None
        
        try:
            # Create default doctor if not exists
            if not default_doctor:
                default_doctor = User(
                    username=encryptor.encrypt("default_doctor"),
                    email=encryptor.encrypt("default.doctor@dejiemr.system"),
                    username_hash=User.create_hash("default_doctor"),
                    email_hash=User.create_hash("default.doctor@dejiemr.system"),
                    role_id=doctor_role.id,
                    is_active=False  # Mark as inactive
                )
                default_doctor.set_password("TempPassword123!")
                db.session.add(default_doctor)
            
            # Create default patient if not exists
            if not default_patient:
                default_patient = User(
                    username=encryptor.encrypt("default_patient"),
                    email=encryptor.encrypt("default.patient@dejiemr.system"),
                    username_hash=User.create_hash("default_patient"),
                    email_hash=User.create_hash("default.patient@dejiemr.system"),
                    role_id=patient_role.id,
                    is_active=False  # Mark as inactive
                )
                default_patient.set_password("TempPassword123!")
                db.session.add(default_patient)
            
            db.session.commit()
            print(f"Created default doctor (ID: {default_doctor.id}) and patient (ID: {default_patient.id})")
            return default_doctor.id, default_patient.id
            
        except Exception as e:
            db.session.rollback()
            print(f"Failed to create default entities: {str(e)}")
            return None, None

def safe_migration():
    """
    Safely migrates the meetings table by handling existing data.
    """
    app = create_app()
    
    with app.app_context():
        print("Starting safe migration for patient-linked meetings...")
        
        try:
            # Step 1: Check if migration is needed
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'meetings' AND table_schema = 'public'
            """)).fetchall()
            
            existing_columns = [row[0] for row in result]
            
            if 'doctor_id' in existing_columns and 'patient_id' in existing_columns:
                print("Migration already completed!")
                return True
            
            # Step 2: Check for existing meetings
            existing_meetings = db.session.execute(text("SELECT COUNT(*) FROM meetings")).fetchone()
            meeting_count = existing_meetings[0] if existing_meetings else 0
            
            print(f"Found {meeting_count} existing meetings")
            
            if meeting_count > 0:
                # Step 3: Create default entities for orphaned meetings
                default_doctor_id, default_patient_id = create_default_entities()
                
                if not default_doctor_id or not default_patient_id:
                    print("ERROR: Could not create default entities")
                    return False
                
                # Step 4: Add columns as nullable first
                print("Adding nullable columns...")
                if 'doctor_id' not in existing_columns:
                    db.session.execute(text("ALTER TABLE meetings ADD COLUMN doctor_id INTEGER"))
                if 'patient_id' not in existing_columns:
                    db.session.execute(text("ALTER TABLE meetings ADD COLUMN patient_id INTEGER"))
                
                db.session.commit()
                
                # Step 5: Update existing meetings with default values
                print("Assigning default values to existing meetings...")
                db.session.execute(text(f"""
                    UPDATE meetings 
                    SET doctor_id = {default_doctor_id}, patient_id = {default_patient_id}
                    WHERE doctor_id IS NULL OR patient_id IS NULL
                """))
                
                db.session.commit()
                
                # Step 6: Add NOT NULL constraints
                print("Adding NOT NULL constraints...")
                db.session.execute(text("ALTER TABLE meetings ALTER COLUMN doctor_id SET NOT NULL"))
                db.session.execute(text("ALTER TABLE meetings ALTER COLUMN patient_id SET NOT NULL"))
                
                db.session.commit()
            
            else:
                # No existing data, can add columns directly as NOT NULL
                print("No existing meetings, adding columns directly...")
                if 'doctor_id' not in existing_columns:
                    db.session.execute(text("ALTER TABLE meetings ADD COLUMN doctor_id INTEGER NOT NULL DEFAULT 1"))
                if 'patient_id' not in existing_columns:
                    db.session.execute(text("ALTER TABLE meetings ADD COLUMN patient_id INTEGER NOT NULL DEFAULT 1"))
                
                db.session.commit()
            
            # Step 7: Add foreign key constraints (PostgreSQL specific)
            print("Adding foreign key constraints...")
            try:
                db.session.execute(text("""
                    ALTER TABLE meetings 
                    ADD CONSTRAINT fk_meetings_doctor_id 
                    FOREIGN KEY (doctor_id) REFERENCES users(id)
                """))
                
                db.session.execute(text("""
                    ALTER TABLE meetings 
                    ADD CONSTRAINT fk_meetings_patient_id 
                    FOREIGN KEY (patient_id) REFERENCES users(id)
                """))
                
                db.session.commit()
                print("Foreign key constraints added successfully")
                
            except Exception as e:
                # Foreign keys might already exist
                print(f"Foreign key constraint warning (this might be normal): {str(e)}")
                db.session.rollback()
            
            print("Migration completed successfully!")
            
            # Step 8: Show summary
            if meeting_count > 0:
                print(f"\nSUMMARY:")
                print(f"- {meeting_count} existing meetings were linked to default entities")
                print(f"- You should manually reassign these meetings to proper patients/doctors")
                print(f"- Default entities are marked as inactive and should not be used for new meetings")
                print(f"- Use the cleanup script to handle these orphaned meetings")
            
            return True
            
        except Exception as e:
            print(f"Migration failed: {str(e)}")
            db.session.rollback()
            return False

def cleanup_orphaned_meetings():
    """
    Provides options for handling meetings linked to default entities.
    """
    app = create_app()
    
    with app.app_context():
        print("Checking for orphaned meetings...")
        
        # Find default entities
        default_doctor = User.query.filter_by(username_hash=User.create_hash("default_doctor")).first()
        default_patient = User.query.filter_by(username_hash=User.create_hash("default_patient")).first()
        
        if not default_doctor or not default_patient:
            print("No default entities found - migration might not have been run")
            return
        
        # Check for meetings using default entities
        orphaned_meetings = db.session.execute(text(f"""
            SELECT id, summary, start_time, attendees 
            FROM meetings 
            WHERE doctor_id = {default_doctor.id} OR patient_id = {default_patient.id}
        """)).fetchall()
        
        if not orphaned_meetings:
            print("No orphaned meetings found!")
            return
        
        print(f"Found {len(orphaned_meetings)} orphaned meetings:")
        
        for meeting in orphaned_meetings:
            meeting_id, summary, start_time, attendees_json = meeting
            attendees = json.loads(attendees_json) if attendees_json else []
            
            print(f"\nMeeting ID: {meeting_id}")
            print(f"Summary: {summary}")
            print(f"Start Time: {start_time}")
            print(f"Attendees: {attendees}")
        
        print(f"\nOptions to handle these meetings:")
        print(f"1. Delete them: python safe_migration_script.py delete-orphaned")
        print(f"2. Manually reassign them using the database")
        print(f"3. Keep them as-is for historical reference")

def delete_orphaned_meetings():
    """Delete meetings linked to default entities."""
    app = create_app()
    
    with app.app_context():
        default_doctor = User.query.filter_by(username_hash=User.create_hash("default_doctor")).first()
        default_patient = User.query.filter_by(username_hash=User.create_hash("default_patient")).first()
        
        if not default_doctor or not default_patient:
            print("Default entities not found")
            return
        
        deleted_count = db.session.execute(text(f"""
            DELETE FROM meetings 
            WHERE doctor_id = {default_doctor.id} OR patient_id = {default_patient.id}
        """)).rowcount
        
        db.session.commit()
        print(f"Deleted {deleted_count} orphaned meetings")

def verify_migration():
    """Verify the migration was successful."""
    app = create_app()
    
    with app.app_context():
        print("Verifying migration...")
        
        # Check columns exist
        result = db.session.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'meetings' AND column_name IN ('doctor_id', 'patient_id')
        """)).fetchall()
        
        found_columns = [row[0] for row in result]
        
        if 'doctor_id' not in found_columns or 'patient_id' not in found_columns:
            print("ERROR: Required columns not found")
            return False
        
        # Check for NULL values
        null_check = db.session.execute(text("""
            SELECT COUNT(*) FROM meetings 
            WHERE doctor_id IS NULL OR patient_id IS NULL
        """)).fetchone()
        
        null_count = null_check[0] if null_check else 0
        
        if null_count > 0:
            print(f"WARNING: {null_count} meetings have NULL doctor_id or patient_id")
            return False
        
        # Check total meetings
        total_meetings = db.session.execute(text("SELECT COUNT(*) FROM meetings")).fetchone()
        total_count = total_meetings[0] if total_meetings else 0
        
        print(f"✓ Migration verified successfully")
        print(f"✓ Total meetings: {total_count}")
        print(f"✓ All meetings have proper doctor/patient links")
        
        return True

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "migrate":
            success = safe_migration()
            if success:
                print("\n✓ Migration completed! You can now use 'flask db upgrade' safely.")
            else:
                print("\n✗ Migration failed. Please check the errors above.")
                
        elif command == "cleanup":
            cleanup_orphaned_meetings()
            
        elif command == "delete-orphaned":
            delete_orphaned_meetings()
            
        elif command == "verify":
            verify_migration()
            
        else:
            print("Unknown command. Available commands: migrate, cleanup, delete-orphaned, verify")
    else:
        print("Safe Migration Script for Patient-Linked Meetings")
        print("=" * 50)
        print()
        print("Available commands:")
        print("  migrate         - Safely add doctor_id and patient_id columns")
        print("  cleanup         - Show orphaned meetings that need attention")
        print("  delete-orphaned - Delete meetings linked to default entities")
        print("  verify          - Verify migration was successful")
        print()
        print("Usage: python safe_migration_script.py [command]")
        print()
        print("IMPORTANT: Run this BEFORE your flask db upgrade command!")
        print("This script will prepare your database for the new schema.")