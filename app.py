"""
JobShield AI - Flask Backend Application
REST API for fraudulent job offer detection
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import os
import logging

from models import db, Job, RedFlag
from ai_logic import analyze_job_offer

# ========================================
# CONFIGURATION
# ========================================

app = Flask(__name__)

# Environment configuration
ENVIRONMENT = os.getenv('FLASK_ENV', 'development')
DEBUG_MODE = ENVIRONMENT == 'development'

# Database configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, '..', 'instance', 'jobshield.db')
os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_SORT_KEYS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# CORS Configuration
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', '*').split(',')
cors_config = {
    r"/api/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
}

# Initialize extensions
db.init_app(app)
CORS(app, resources=cors_config)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ========================================
# ERROR HANDLERS
# ========================================

@app.errorhandler(400)
def bad_request(error):
    """Handle 400 Bad Request"""
    return jsonify({
        'success': False,
        'error': 'Bad Request',
        'message': str(error.description)
    }), 400


@app.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found"""
    return jsonify({
        'success': False,
        'error': 'Not Found',
        'message': 'The requested resource was not found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 Internal Server Error"""
    logger.error(f'Internal Server Error: {error}')
    db.session.rollback()
    return jsonify({
        'success': False,
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred. Please try again.'
    }), 500


# ========================================
# HEALTH CHECK ENDPOINT
# ========================================

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint to verify API is running
    
    Returns:
        JSON response with health status
    """
    return jsonify({
        'success': True,
        'message': 'JobShield AI API is running',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    }), 200


# ========================================
# MAIN ANALYSIS ENDPOINT
# ========================================

@app.route('/api/analyze', methods=['POST'])
def analyze_job():
    """
    Main endpoint for job fraud detection analysis
    
    Expected JSON payload:
    {
        "company_name": "Company Name",
        "job_title": "Job Title",
        "description": "Full job description...",
        "email": "contact@company.com",
        "website": "https://company.com" (optional),
        "salary": "Salary/Stipend" (optional)
    }
    
    Returns:
        JSON response with:
        - risk_score (0-100)
        - classification (Legitimate/Suspicious/Fake)
        - detected_flags (list of red flags)
        - explanation (brief summary)
        - job_id (database record ID)
    """
    try:
        # Validate request
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Invalid Content-Type',
                'message': 'Request must be JSON'
            }), 400

        data = request.get_json()

        # Validate required fields
        required_fields = ['company_name', 'job_title', 'description', 'email']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'error': 'Missing Required Field',
                    'message': f'Field "{field}" is required and cannot be empty'
                }), 400

        # Extract and sanitize input
        company_name = str(data.get('company_name', '')).strip()
        job_title = str(data.get('job_title', '')).strip()
        description = str(data.get('description', '')).strip()
        email = str(data.get('email', '')).strip().lower()
        website = str(data.get('website', '')).strip() if data.get('website') else None
        salary = str(data.get('salary', '')).strip() if data.get('salary') else None

        # Validate email format
        if '@' not in email or '.' not in email.split('@')[-1]:
            return jsonify({
                'success': False,
                'error': 'Invalid Email',
                'message': 'Please provide a valid email address'
            }), 400

        # Run analysis through AI engine
        risk_score, classification, detected_flags = analyze_job_offer(
            company_name=company_name,
            job_title=job_title,
            description=description,
            email=email,
            website=website,
            salary=salary
        )

        # Save to database
        try:
            job_record = Job(
                company_name=company_name,
                job_title=job_title,
                description=description,
                email=email,
                website=website,
                salary=salary,
                risk_score=risk_score,
                classification=classification
            )
            db.session.add(job_record)
            db.session.flush()  # Get the ID without committing

            # Add red flags
            for flag in detected_flags:
                red_flag = RedFlag(
                    job_id=job_record.id,
                    flag_type=flag['type'],
                    description=flag['description'],
                    severity=flag['severity']
                )
                db.session.add(red_flag)

            db.session.commit()
            logger.info(f'✓ Analysis saved: Job ID {job_record.id} - {company_name}')

        except Exception as db_error:
            db.session.rollback()
            logger.error(f'Database error: {db_error}')
            # Continue with response even if DB save fails

        # Build response
        response = {
            'success': True,
            'risk_score': risk_score,
            'classification': classification,
            'detected_flags': detected_flags,
            'explanation': _get_explanation(risk_score, classification),
            'timestamp': datetime.utcnow().isoformat(),
        }

        # Add job_id if successfully saved
        try:
            response['job_id'] = job_record.id
        except:
            pass

        return jsonify(response), 200

    except Exception as e:
        logger.error(f'Unexpected error in /api/analyze: {str(e)}')
        return jsonify({
            'success': False,
            'error': 'Analysis Failed',
            'message': 'An error occurred during analysis. Please try again.'
        }), 500


# ========================================
# RESULTS RETRIEVAL ENDPOINT
# ========================================

@app.route('/api/results/<int:job_id>', methods=['GET'])
def get_result(job_id):
    """
    Retrieve a previous analysis result by job ID
    
    Args:
        job_id: Database ID of the job analysis
    
    Returns:
        JSON response with complete analysis data
    """
    try:
        job = Job.query.get(job_id)

        if not job:
            return jsonify({
                'success': False,
                'error': 'Not Found',
                'message': f'Analysis result with ID {job_id} not found'
            }), 404

        response = {
            'success': True,
            'data': job.to_dict(),
            'timestamp': datetime.utcnow().isoformat()
        }

        return jsonify(response), 200

    except Exception as e:
        logger.error(f'Error retrieving result: {str(e)}')
        return jsonify({
            'success': False,
            'error': 'Retrieval Failed',
            'message': 'Failed to retrieve analysis result'
        }), 500


# ========================================
# STATISTICS ENDPOINT
# ========================================

@app.route('/api/stats', methods=['GET'])
def get_statistics():
    """
    Get statistics about job analyses
    
    Returns:
        JSON response with:
        - total_analyses: Total number of analyses performed
        - legitimate: Count of legitimate offers
        - suspicious: Count of suspicious offers
        - fake: Count of fake offers
    """
    try:
        total = Job.query.count()
        legitimate = Job.query.filter_by(classification='Legitimate').count()
        suspicious = Job.query.filter_by(classification='Suspicious').count()
        fake = Job.query.filter_by(classification='Fake').count()

        response = {
            'success': True,
            'statistics': {
                'total_analyses': total,
                'legitimate': legitimate,
                'suspicious': suspicious,
                'fake': fake,
                'average_risk_score': round(
                    db.session.query(db.func.avg(Job.risk_score)).scalar() or 0, 2
                )
            },
            'timestamp': datetime.utcnow().isoformat()
        }

        return jsonify(response), 200

    except Exception as e:
        logger.error(f'Error retrieving statistics: {str(e)}')
        return jsonify({
            'success': False,
            'error': 'Statistics Failed',
            'message': 'Failed to retrieve statistics'
        }), 500


# ========================================
# HELPER FUNCTIONS
# ========================================

def _get_explanation(risk_score: int, classification: str) -> str:
    """
    Generate a human-readable explanation for the result
    
    Args:
        risk_score: Numerical risk score (0-100)
        classification: Risk classification
    
    Returns:
        Explanation string
    """
    if classification == 'Legitimate':
        return (
            'This job offer appears to be legitimate based on our analysis. '
            'However, always verify company details independently before proceeding.'
        )
    elif classification == 'Suspicious':
        return (
            'This job offer has several characteristics that require caution. '
            'We recommend verifying company details, speaking with current employees, '
            'and consulting your college placement cell before applying.'
        )
    elif classification == 'Fake':
        return (
            'This job offer shows multiple red flags consistent with fraudulent schemes. '
            'We strongly recommend NOT proceeding with this opportunity. '
            'Report this to your college authorities if received officially.'
        )
    return 'Unable to classify this offer. Use your judgment.'


# ========================================
# DATABASE INITIALIZATION
# ========================================

@app.before_request
def before_request():
    """Ensure database tables exist before processing requests"""
    try:
        # Create tables if they don't exist
        with app.app_context():
            db.create_all()
    except Exception as e:
        logger.error(f'Database initialization error: {e}')


# ========================================
# APPLICATION ENTRY POINT
# ========================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        logger.info('✓ Database initialized')

    logger.info('🚀 Starting JobShield AI Flask Server...')
    logger.info(f'📊 Database: {DATABASE_PATH}')
    logger.info(f'🌐 Environment: {ENVIRONMENT}')
    logger.info(f'🌐 CORS enabled for origins: {ALLOWED_ORIGINS}')
    logger.info('📡 Visit http://localhost:5000/health to verify API is running')

    # Development server
    if DEBUG_MODE:
        logger.warning('⚠️  DEBUG MODE ENABLED - Do not use in production!')
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True,
            use_reloader=True
        )
    else:
        # Production: Use with Gunicorn or similar WSGI server
        logger.info('🔒 Running in PRODUCTION mode')
        logger.info('📌 Use a WSGI server like Gunicorn to run this app')
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=False,
            use_reloader=False
        )
