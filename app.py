from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from datetime import datetime, timedelta
import os

app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app, resources={r"/api/*": {"origins": "*"}})

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(BASE_DIR, 'taskflow.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'taskflow-super-secret-key-2024')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ─── Models ──────────────────────────────────────────────────────────────────

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='member')  # admin | member
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tasks_assigned = db.relationship('Task', foreign_keys='Task.assignee_id', backref='assignee', lazy=True)
    tasks_created = db.relationship('Task', foreign_keys='Task.creator_id', backref='creator', lazy=True)

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'email': self.email, 'role': self.role, 'created_at': self.created_at.isoformat()}

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tasks = db.relationship('Task', backref='project', lazy=True, cascade='all, delete-orphan')
    members = db.relationship('ProjectMember', backref='project', lazy=True, cascade='all, delete-orphan')
    owner = db.relationship('User', foreign_keys=[owner_id])

    def to_dict(self, include_members=False):
        d = {
            'id': self.id, 'name': self.name, 'description': self.description,
            'owner_id': self.owner_id, 'created_at': self.created_at.isoformat(),
            'owner_name': self.owner.name if self.owner else None,
            'task_count': len(self.tasks),
            'member_count': len(self.members),
        }
        if include_members:
            d['members'] = [m.to_dict() for m in self.members]
        return d

class ProjectMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(20), default='member')  # admin | member
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', foreign_keys=[user_id])

    def to_dict(self):
        return {'id': self.id, 'project_id': self.project_id, 'user_id': self.user_id,
                'role': self.role, 'name': self.user.name if self.user else None,
                'email': self.user.email if self.user else None}

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(30), default='todo')  # todo | in_progress | done
    priority = db.Column(db.String(20), default='medium')  # low | medium | high
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    due_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'title': self.title, 'description': self.description,
            'status': self.status, 'priority': self.priority,
            'project_id': self.project_id,
            'project_name': self.project.name if self.project else None,
            'assignee_id': self.assignee_id,
            'assignee_name': self.assignee.name if self.assignee else None,
            'creator_id': self.creator_id,
            'creator_name': self.creator.name if self.creator else None,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'is_overdue': (self.due_date < datetime.utcnow() and self.status != 'done') if self.due_date else False
        }

# ─── Helpers ─────────────────────────────────────────────────────────────────

def get_current_user():
    uid = get_jwt_identity()
    return User.query.get(int(uid))

def is_project_admin(user, project_id):
    if user.role == 'admin':
        return True
    member = ProjectMember.query.filter_by(project_id=project_id, user_id=user.id).first()
    return member and member.role == 'admin'

def can_access_project(user, project_id):
    if user.role == 'admin':
        return True
    return ProjectMember.query.filter_by(project_id=project_id, user_id=user.id).first() is not None

# ─── Auth Routes ─────────────────────────────────────────────────────────────

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.json
    if not data or not all(k in data for k in ['name', 'email', 'password']):
        return jsonify({'error': 'Name, email and password are required'}), 400
    if len(data['password']) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 409
    hashed = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    # First user becomes admin
    role = 'admin' if User.query.count() == 0 else data.get('role', 'member')
    user = User(name=data['name'], email=data['email'], password=hashed, role=role)
    db.session.add(user)
    db.session.commit()
    token = create_access_token(identity=str(user.id))
    return jsonify({'token': token, 'user': user.to_dict()}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    if not data or not all(k in data for k in ['email', 'password']):
        return jsonify({'error': 'Email and password are required'}), 400
    user = User.query.filter_by(email=data['email']).first()
    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({'error': 'Invalid email or password'}), 401
    token = create_access_token(identity=str(user.id))
    return jsonify({'token': token, 'user': user.to_dict()})

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def me():
    user = get_current_user()
    return jsonify(user.to_dict())

# ─── User Routes ─────────────────────────────────────────────────────────────

@app.route('/api/users', methods=['GET'])
@jwt_required()
def get_users():
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])

@app.route('/api/users/<int:uid>', methods=['PUT'])
@jwt_required()
def update_user(uid):
    current = get_current_user()
    if current.id != uid and current.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    user = User.query.get_or_404(uid)
    data = request.json
    if 'name' in data:
        user.name = data['name']
    if 'role' in data and current.role == 'admin':
        user.role = data['role']
    db.session.commit()
    return jsonify(user.to_dict())

# ─── Project Routes ───────────────────────────────────────────────────────────

@app.route('/api/projects', methods=['GET'])
@jwt_required()
def get_projects():
    user = get_current_user()
    if user.role == 'admin':
        projects = Project.query.all()
    else:
        member_project_ids = [m.project_id for m in ProjectMember.query.filter_by(user_id=user.id).all()]
        projects = Project.query.filter(Project.id.in_(member_project_ids)).all()
    return jsonify([p.to_dict() for p in projects])

@app.route('/api/projects', methods=['POST'])
@jwt_required()
def create_project():
    user = get_current_user()
    data = request.json
    if not data or not data.get('name'):
        return jsonify({'error': 'Project name is required'}), 400
    project = Project(name=data['name'], description=data.get('description', ''), owner_id=user.id)
    db.session.add(project)
    db.session.flush()
    # Auto-add creator as admin member
    member = ProjectMember(project_id=project.id, user_id=user.id, role='admin')
    db.session.add(member)
    db.session.commit()
    return jsonify(project.to_dict()), 201

@app.route('/api/projects/<int:pid>', methods=['GET'])
@jwt_required()
def get_project(pid):
    user = get_current_user()
    project = Project.query.get_or_404(pid)
    if not can_access_project(user, pid):
        return jsonify({'error': 'Forbidden'}), 403
    d = project.to_dict(include_members=True)
    d['tasks'] = [t.to_dict() for t in project.tasks]
    return jsonify(d)

@app.route('/api/projects/<int:pid>', methods=['PUT'])
@jwt_required()
def update_project(pid):
    user = get_current_user()
    project = Project.query.get_or_404(pid)
    if not is_project_admin(user, pid):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    if 'name' in data:
        project.name = data['name']
    if 'description' in data:
        project.description = data['description']
    db.session.commit()
    return jsonify(project.to_dict())

@app.route('/api/projects/<int:pid>', methods=['DELETE'])
@jwt_required()
def delete_project(pid):
    user = get_current_user()
    project = Project.query.get_or_404(pid)
    if not is_project_admin(user, pid):
        return jsonify({'error': 'Forbidden'}), 403
    db.session.delete(project)
    db.session.commit()
    return jsonify({'message': 'Project deleted'})

@app.route('/api/projects/<int:pid>/members', methods=['POST'])
@jwt_required()
def add_member(pid):
    user = get_current_user()
    if not is_project_admin(user, pid):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    target = User.query.filter_by(email=data.get('email')).first()
    if not target:
        return jsonify({'error': 'User not found'}), 404
    existing = ProjectMember.query.filter_by(project_id=pid, user_id=target.id).first()
    if existing:
        return jsonify({'error': 'User already a member'}), 409
    member = ProjectMember(project_id=pid, user_id=target.id, role=data.get('role', 'member'))
    db.session.add(member)
    db.session.commit()
    return jsonify(member.to_dict()), 201

@app.route('/api/projects/<int:pid>/members/<int:uid>', methods=['DELETE'])
@jwt_required()
def remove_member(pid, uid):
    user = get_current_user()
    if not is_project_admin(user, pid):
        return jsonify({'error': 'Forbidden'}), 403
    member = ProjectMember.query.filter_by(project_id=pid, user_id=uid).first_or_404()
    db.session.delete(member)
    db.session.commit()
    return jsonify({'message': 'Member removed'})

# ─── Task Routes ─────────────────────────────────────────────────────────────

@app.route('/api/tasks', methods=['GET'])
@jwt_required()
def get_all_tasks():
    user = get_current_user()
    if user.role == 'admin':
        tasks = Task.query.all()
    else:
        member_project_ids = [m.project_id for m in ProjectMember.query.filter_by(user_id=user.id).all()]
        tasks = Task.query.filter(Task.project_id.in_(member_project_ids)).all()
    return jsonify([t.to_dict() for t in tasks])

@app.route('/api/projects/<int:pid>/tasks', methods=['GET'])
@jwt_required()
def get_tasks(pid):
    user = get_current_user()
    if not can_access_project(user, pid):
        return jsonify({'error': 'Forbidden'}), 403
    tasks = Task.query.filter_by(project_id=pid).all()
    return jsonify([t.to_dict() for t in tasks])

@app.route('/api/projects/<int:pid>/tasks', methods=['POST'])
@jwt_required()
def create_task(pid):
    user = get_current_user()
    if not can_access_project(user, pid):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    if not data or not data.get('title'):
        return jsonify({'error': 'Title is required'}), 400
    due = None
    if data.get('due_date'):
        try:
            due = datetime.fromisoformat(data['due_date'].replace('Z', '+00:00').replace('+00:00', ''))
        except:
            pass
    task = Task(
        title=data['title'], description=data.get('description', ''),
        status=data.get('status', 'todo'), priority=data.get('priority', 'medium'),
        project_id=pid, assignee_id=data.get('assignee_id'),
        creator_id=user.id, due_date=due
    )
    db.session.add(task)
    db.session.commit()
    return jsonify(task.to_dict()), 201

@app.route('/api/tasks/<int:tid>', methods=['PUT'])
@jwt_required()
def update_task(tid):
    user = get_current_user()
    task = Task.query.get_or_404(tid)
    if not can_access_project(user, task.project_id):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    for field in ['title', 'description', 'status', 'priority', 'assignee_id']:
        if field in data:
            setattr(task, field, data[field])
    if 'due_date' in data:
        try:
            task.due_date = datetime.fromisoformat(data['due_date'].replace('Z', '+00:00').replace('+00:00', '')) if data['due_date'] else None
        except:
            pass
    task.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify(task.to_dict())

@app.route('/api/tasks/<int:tid>', methods=['DELETE'])
@jwt_required()
def delete_task(tid):
    user = get_current_user()
    task = Task.query.get_or_404(tid)
    if not is_project_admin(user, task.project_id) and task.creator_id != user.id:
        return jsonify({'error': 'Forbidden'}), 403
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted'})

# ─── Dashboard ───────────────────────────────────────────────────────────────

@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    user = get_current_user()
    now = datetime.utcnow()
    if user.role == 'admin':
        all_tasks = Task.query.all()
        all_projects = Project.query.all()
        my_tasks = Task.query.filter_by(assignee_id=user.id).all()
    else:
        member_project_ids = [m.project_id for m in ProjectMember.query.filter_by(user_id=user.id).all()]
        all_tasks = Task.query.filter(Task.project_id.in_(member_project_ids)).all()
        all_projects = Project.query.filter(Project.id.in_(member_project_ids)).all()
        my_tasks = [t for t in all_tasks if t.assignee_id == user.id]

    overdue = [t for t in all_tasks if t.due_date and t.due_date < now and t.status != 'done']
    return jsonify({
        'stats': {
            'total_projects': len(all_projects),
            'total_tasks': len(all_tasks),
            'todo': sum(1 for t in all_tasks if t.status == 'todo'),
            'in_progress': sum(1 for t in all_tasks if t.status == 'in_progress'),
            'done': sum(1 for t in all_tasks if t.status == 'done'),
            'overdue': len(overdue),
            'my_tasks': len(my_tasks),
        },
        'my_tasks': [t.to_dict() for t in my_tasks[:10]],
        'overdue_tasks': [t.to_dict() for t in overdue[:5]],
        'recent_tasks': [t.to_dict() for t in sorted(all_tasks, key=lambda x: x.created_at, reverse=True)[:5]]
    })

# ─── Frontend Serving ─────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    file_path = os.path.join(app.static_folder, path)
    if os.path.exists(file_path):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
