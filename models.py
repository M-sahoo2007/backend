"""
Database models using SQLAlchemy ORM
Defines the structure for Job Analysis and Red Flags data
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class Job(db.Model):
    """
    Job Analysis Record
    Stores all job offer submissions and their analysis results
    """
    __tablename__ = 'jobs'

    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(255), nullable=False, index=True)
    job_title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(255), nullable=False)
    website = db.Column(db.String(500), nullable=True)
    salary = db.Column(db.String(255), nullable=True)
    
    # Analysis Results
    risk_score = db.Column(db.Integer, nullable=False)
    classification = db.Column(db.String(50), nullable=False)  # 'Legitimate', 'Suspicious', 'Fake'
    
    # Metadata
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    # Relationships
    flags = db.relationship('RedFlag', back_populates='job', cascade='all, delete-orphan')

    def to_dict(self):
        """Convert job record to dictionary"""
        return {
            'id': self.id,
            'company_name': self.company_name,
            'job_title': self.job_title,
            'description': self.description,
            'email': self.email,
            'website': self.website,
            'salary': self.salary,
            'risk_score': self.risk_score,
            'classification': self.classification,
            'created_at': self.created_at.isoformat(),
            'flags': [flag.to_dict() for flag in self.flags],
        }

    def __repr__(self):
        return f'<Job {self.id}: {self.company_name} - {self.job_title}>'


class RedFlag(db.Model):
    """
    Red Flag Detection Record
    Stores individual fraud indicators detected in job offers
    """
    __tablename__ = 'flags'

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('jobs.id'), nullable=False, index=True)
    flag_type = db.Column(db.String(255), nullable=False)  # 'Free Email Domain', 'Unrealistic Salary', etc.
    description = db.Column(db.Text, nullable=False)  # Detailed explanation of the flag
    severity = db.Column(db.String(50), nullable=False, default='medium')  # 'critical', 'high', 'medium', 'low'
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    job = db.relationship('Job', back_populates='flags')

    def to_dict(self):
        """Convert flag record to dictionary"""
        return {
            'id': self.id,
            'job_id': self.job_id,
            'type': self.flag_type,
            'description': self.description,
            'severity': self.severity,
            'created_at': self.created_at.isoformat(),
        }

    def __repr__(self):
        return f'<RedFlag {self.id}: {self.flag_type} (Job {self.job_id})>'
