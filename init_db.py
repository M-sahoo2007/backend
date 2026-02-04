"""
Database Initialization Script
Creates the database schema and optionally seeds with sample data
Run this script once to set up the database
"""

import os
import sys
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import Job, RedFlag


def initialize_database():
    """Initialize the database with required tables"""
    print('=' * 50)
    print('JobShield AI - Database Initialization')
    print('=' * 50)

    try:
        with app.app_context():
            # Create all tables
            print('\n📊 Creating database tables...')
            db.create_all()
            print('✓ Tables created successfully')

            # Display table information
            print('\n📋 Database Tables:')
            print('  - jobs: Stores job offer analyses and results')
            print('  - flags: Stores detected red flags for each job')

            print('\n📍 Database Location:')
            db_path = os.path.abspath(os.path.join(
                os.path.dirname(__file__), '..', 'instance', 'jobshield.db'
            ))
            print(f'  {db_path}')

            print('\n✅ Database initialized successfully!')
            print('\nYou can now:')
            print('  1. Start the Flask server: python app.py')
            print('  2. Open the frontend: open frontend/index.html in a browser')
            print('  3. Begin analyzing job offers!')

    except Exception as e:
        print(f'\n❌ Error initializing database: {str(e)}')
        sys.exit(1)


def seed_sample_data():
    """
    Seed the database with sample job analysis data for testing
    Uncomment the function call in main() to use this
    """
    print('\n📝 Seeding sample data...')

    sample_jobs = [
        {
            'company_name': 'TechStart Innovations',
            'job_title': 'Software Engineer Intern',
            'description': '''
            Dear Applicant,
            We are looking for interns for our software development team.
            Work from home, flexible hours. Earn 50,000 per day!
            Limited spots available - Apply immediately!
            Please send a registration fee of 5000 for processing.
            Contact us ASAP at techstart.jobs@gmail.com
            ''',
            'email': 'techstart.jobs@gmail.com',
            'website': None,
            'salary': '50000 per day',
            'risk_score': 85,
            'classification': 'Fake'
        },
        {
            'company_name': 'Google India',
            'job_title': 'Software Engineer',
            'description': '''
            We are hiring experienced software engineers for our India office.
            Location: Bangalore, India
            About the role:
            - Design and develop scalable distributed systems
            - Work with modern technologies and frameworks
            - Collaborate with world-class engineers
            
            Qualifications:
            - 3+ years of software development experience
            - Strong DSA fundamentals
            - Experience with cloud platforms
            
            Benefits: Competitive salary, health insurance, learning budget
            ''',
            'email': 'careers@google.com',
            'website': 'https://google.com/careers',
            'salary': '20-30 LPA',
            'risk_score': 15,
            'classification': 'Legitimate'
        },
        {
            'company_name': 'StartUp XYZ Ltd International',
            'job_title': 'Junior Data Analyst',
            'description': '''
            Join our rapidly growing team as a Data Analyst!
            No experience necessary! Earn while you learn!
            Work from anywhere, no office required.
            Guaranteed promotion within 3 months.
            Urgent hiring - please apply immediately.
            ''',
            'email': 'hr@startupxyz.co',
            'website': None,
            'salary': '100,000 per month',
            'risk_score': 68,
            'classification': 'Suspicious'
        }
    ]

    try:
        with app.app_context():
            for job_data in sample_jobs:
                # Check if job already exists
                existing = Job.query.filter_by(
                    company_name=job_data['company_name'],
                    job_title=job_data['job_title']
                ).first()

                if not existing:
                    job = Job(
                        company_name=job_data['company_name'],
                        job_title=job_data['job_title'],
                        description=job_data['description'].strip(),
                        email=job_data['email'],
                        website=job_data['website'],
                        salary=job_data['salary'],
                        risk_score=job_data['risk_score'],
                        classification=job_data['classification']
                    )
                    db.session.add(job)
                    db.session.flush()

                    # Add sample flags based on risk classification
                    if job_data['risk_score'] > 70:
                        flags = [
                            {
                                'flag_type': 'Payment Request',
                                'description': 'Job posting mentions registration fees',
                                'severity': 'critical'
                            },
                            {
                                'flag_type': 'Unrealistic Salary',
                                'description': f'Salary of {job_data["salary"]} is unrealistic',
                                'severity': 'high'
                            }
                        ]
                    elif job_data['risk_score'] > 30:
                        flags = [
                            {
                                'flag_type': 'No Work Required',
                                'description': 'Job posting claims no experience needed for senior role',
                                'severity': 'high'
                            }
                        ]
                    else:
                        flags = []

                    for flag_data in flags:
                        flag = RedFlag(
                            job_id=job.id,
                            flag_type=flag_data['flag_type'],
                            description=flag_data['description'],
                            severity=flag_data['severity']
                        )
                        db.session.add(flag)

            db.session.commit()
            print('✓ Sample data added successfully')

    except Exception as e:
        db.session.rollback()
        print(f'✗ Error seeding data: {str(e)}')


if __name__ == '__main__':
    initialize_database()
    
    # Uncomment the line below to seed sample data
    # seed_sample_data()

    print('\n' + '=' * 50)
