import datetime
import os
import re
import sys
import tempfile
from traceback import format_exc

from flask import (Response, abort, current_app, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask.views import MethodView
from flask_login import current_user, login_required, login_user
from future.utils import iteritems
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import text
from sqlalchemy import or_
from sqlalchemy.sql.expression import true
from werkzeug import secure_filename

from .. import limiter
from ..auth.forms import LoginForm
from ..auth.utils import ac_or_admin_required, admin_required
from ..models import (Assignment, Department, Description, Face, Image,
                      Incident, Job, LicensePlate, Link, Location, Note,
                      Officer, Salary, Unit, User, db)
from ..utils import (ac_can_edit_officer, add_department_query,
                     add_new_assignment, add_officer_profile, add_unit_query,
                     allowed_file, compute_hash, compute_leaderboard_stats,
                     create_description, create_incident, create_note,
                     active_dept_choices, all_dept_choices, edit_existing_assignment,
                     edit_officer_profile, filter_by_form, get_or_create,
                     get_random_image, get_uploaded_cropped_image,
                     replace_list, roster_lookup, serve_image,
                     set_dynamic_default, upload_file, get_random_image_from_active_department)
from . import main
from .choices import AGE_CHOICES, GENDER_CHOICES, RACE_CHOICES
from .forms import (AddImageForm, AddImageFormAdmin, AddOfficerForm, AddUnitForm, AssignmentForm,
                    BrowseForm, ChangeDepartmentStatusForm, DepartmentForm,
                    EditDepartmentForm, EditOfficerForm, EditTextForm, FaceTag,
                    FindOfficerForm, FindOfficerFormAdmin, FindOfficerIDForm,
                    FindOfficerIDFormAdmin, IncidentForm,
                    SalaryForm, TextForm)
from .model_view import ModelView

# Ensure the file is read/write by the creator only
SAVED_UMASK = os.umask(0o077)


def redirect_url(default='index'):
    return request.args.get('next') or request.referrer or url_for(default)


@main.route('/')
@main.route('/index')
def index():
    return render_template('index.html')


@main.route('/browse', methods=['GET'])
def browse():
    active_departments = active_dept_choices()
    all_departments = all_dept_choices()
    if current_user.is_anonymous or not (current_user.is_administrator or current_user.is_area_coordinator):
        return render_template('browse.html', departments=active_departments)
    if current_user.is_administrator:
        return render_template('browse.html', departments=all_departments)
    if current_user.is_area_coordinator:
        ac_dept = Department.query.filter_by(id=current_user.ac_department_id).one()
        if ac_dept not in active_departments:
            active_departments.append(ac_dept)
            return render_template('browse.html', departments=active_departments)
        return render_template('browse.html', departments=active_departments)


@main.route('/find', methods=['GET', 'POST'])
def get_officer():
    jsloads = ['js/find_officer.js']
    form = FindOfficerForm()
    depts_dict = [dept_choice.toCustomDict() for dept_choice in active_dept_choices()]
    if not current_user.is_anonymous and current_user.is_administrator:
        form = FindOfficerFormAdmin()
        depts_dict = [dept_choice.toCustomDict() for dept_choice in all_dept_choices()]

    if getattr(current_user, 'dept_pref_rel', None):
        set_dynamic_default(form.dept, current_user.dept_pref_rel)

    if form.validate_on_submit():
        return redirect(url_for(
            'main.list_officer',
            department_id=form.data['dept'].id,
            race=form.data['race'] if form.data['race'] != 'Not Sure' else None,
            gender=form.data['gender'] if form.data['gender'] != 'Not Sure' else None,
            rank=form.data['rank'] if form.data['rank'] != 'Not Sure' else None,
            min_age=form.data['min_age'],
            max_age=form.data['max_age'],
            name=form.data['name'],
            badge=form.data['badge'],
            unique_internal_identifier=form.data['unique_internal_identifier']),
            code=302)
    return render_template('input_find_officer.html', form=form, depts_dict=depts_dict, jsloads=jsloads)


@main.route('/tagger_find', methods=['GET', 'POST'])
def get_ooid():
    if not current_user.is_anonymous and current_user.is_administrator:
        form = FindOfficerIDFormAdmin()
    else:
        form = FindOfficerIDForm()
    if form.validate_on_submit():
        return redirect(url_for('main.get_tagger_gallery'), code=307)
    return render_template('input_find_ooid.html', form=form)


@main.route('/label', methods=['GET', 'POST'])
def get_started_labeling():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    depts = active_dept_choices()
    if not current_user.is_anonymous and current_user.is_administrator:
        depts = all_dept_choices()
    if not current_user.is_anonymous and current_user.is_area_coordinator:
        ac_dept = current_user.ac_department
        if ac_dept not in depts:
            depts.append(ac_dept)
    return render_template('label_data.html', departments=depts, form=form)


@main.route('/sort/department/<int:department_id>', methods=['GET', 'POST'])
@login_required
def sort_images(department_id):
    dept_ids = [dept.id for dept in all_dept_choices()]
    if department_id not in dept_ids:
        abort(404)
    department = Department.query.filter_by(id=department_id).one_or_none()
    if not department.is_active and not(current_user.is_administrator or current_user.ac_department_id == department_id):
        abort(404)
    image_query = Image.query.filter_by(contains_cops=None) \
                             .filter_by(department_id=department_id)
    image = get_random_image(image_query)

    if image:
        proper_path = serve_image(image.filepath)
    else:
        proper_path = None
    return render_template('sort.html', image=image, path=proper_path,
                           department_id=department_id)


@main.route('/tutorial')
def get_tutorial():
    return render_template('tutorial.html')


@main.route('/user/<username>')
def profile(username):
    if re.search('^[A-Za-z][A-Za-z0-9_.]*$', username):
        user = User.query.filter_by(username=username).one()
    else:
        abort(404)
    try:
        pref = User.query.filter_by(id=current_user.id).one().dept_pref
        department = Department.query.filter_by(id=pref).one().name
    except NoResultFound:
        department = None
    if not current_user.is_area_coordinator and not current_user.is_administrator:
        classifications = [classification for classification in user.classifications if classification.department.is_active]
        tags = [tag for tag in user.tags if tag.image.department.is_active]
    if current_user.is_administrator:
        classifications = user.classifications
        tags = user.tags
    if current_user.is_area_coordinator:
        active_classifications = [classification for classification in user.classifications if classification.department.is_active]
        inactive_classifications = [classification for classification in user.classifications if not classification.department.is_active and classification.department_id == current_user.ac_department_id]
        classifications = active_classifications + inactive_classifications
        active_tags = [tag for tag in user.tags if tag.image.department.is_active]
        inactive_tags = [tag for tag in user.tags if not tag.image.department.is_active and tag.image.department.id == current_user.ac_department_id]
        tags = active_tags + inactive_tags
    return render_template('profile.html', user=user, department=department, classifications=classifications, tags=tags)


@main.route('/officer/<int:officer_id>', methods=['GET', 'POST'])
def officer_profile(officer_id):
    form = AssignmentForm()
    department_id = Officer.query.filter_by(id=officer_id).one().department_id
    department = Department.query.filter_by(id=department_id).one()
    if not department.is_active and (current_user.is_anonymous or not (current_user.is_administrator or (current_user.is_area_coordinator and current_user.ac_department_id == department_id))):
        abort(403)
    try:
        officer = Officer.query.filter_by(id=officer_id).one()
    except NoResultFound:
        abort(404)
    except:  # noqa
        exception_type, value, full_tback = sys.exc_info()
        current_app.logger.error('Error finding officer: {}'.format(
            ' '.join([str(exception_type), str(value),
                      format_exc()])
        ))
    form.job_title.query = Job.query\
                              .filter_by(department_id=officer.department_id)\
                              .order_by(Job.order.asc())\
                              .all()

    try:
        faces = Face.query.filter_by(officer_id=officer_id).all()
        assignments = Assignment.query.filter_by(officer_id=officer_id).all()
        face_paths = []
        for face in faces:
            face_paths.append(serve_image(face.image.filepath))
    except:  # noqa
        exception_type, value, full_tback = sys.exc_info()
        current_app.logger.error('Error loading officer profile: {}'.format(
            ' '.join([str(exception_type), str(value),
                      format_exc()])
        ))

    return render_template('officer.html', officer=officer, paths=face_paths,
                           faces=faces, assignments=assignments, form=form)


@main.route('/officer/<int:officer_id>/assignment/new', methods=['POST'])
@ac_or_admin_required
def add_assignment(officer_id):
    form = AssignmentForm()
    officer = Officer.query.filter_by(id=officer_id).first()
    form.job_title.query = Job.query\
                              .filter_by(department_id=officer.department_id)\
                              .order_by(Job.order.asc())\
                              .all()
    if not officer:
        flash('Officer not found')
        abort(404)

    if form.validate_on_submit() and (current_user.is_administrator or
                                      (current_user.is_area_coordinator and
                                       officer.department_id == current_user.ac_department_id)):
        try:
            add_new_assignment(officer_id, form)
            flash('Added new assignment!')
        except IntegrityError:
            flash('Assignment already exists')
        return redirect(url_for('main.officer_profile',
                                officer_id=officer_id), code=302)
    elif current_user.is_area_coordinator and not officer.department_id == current_user.ac_department_id:
        abort(403)

    return redirect(url_for('main.officer_profile', officer_id=officer_id))


@main.route('/officer/<int:officer_id>/assignment/<int:assignment_id>',
            methods=['GET', 'POST'])
@login_required
@ac_or_admin_required
def edit_assignment(officer_id, assignment_id):
    officer = Officer.query.filter_by(id=officer_id).one()

    if current_user.is_area_coordinator and not current_user.is_administrator:
        if not ac_can_edit_officer(officer, current_user):
            abort(403)

    assignment = Assignment.query.filter_by(id=assignment_id).one()
    form = AssignmentForm(obj=assignment)
    form.job_title.query = Job.query\
                              .filter_by(department_id=officer.department_id)\
                              .order_by(Job.order.asc())\
                              .all()
    form.job_title.data = Job.query.filter_by(id=assignment.job_id).one()
    if form.unit.data and type(form.unit.data) == int:
        form.unit.data = Unit.query.filter_by(id=form.unit.data).one()
    if form.validate_on_submit():
        form.job_title.data = Job.query.filter_by(id=int(form.job_title.raw_data[0])).one()
        assignment = edit_existing_assignment(assignment, form)
        flash('Edited officer assignment ID {}'.format(assignment.id))
        return redirect(url_for('main.officer_profile', officer_id=officer_id))
    return render_template('edit_assignment.html', form=form)


@main.route('/officer/<int:officer_id>/salary/new', methods=['GET', 'POST'])
@ac_or_admin_required
def add_salary(officer_id):
    form = SalaryForm()
    officer = Officer.query.filter_by(id=officer_id).first()
    if not officer:
        flash('Officer not found')
        abort(404)

    if form.validate_on_submit() and (current_user.is_administrator or
                                      (current_user.is_area_coordinator and
                                       officer.department_id == current_user.ac_department_id)):
        try:
            new_salary = Salary(
                officer_id=officer_id,
                salary=form.salary.data,
                overtime_pay=form.overtime_pay.data,
                year=form.year.data,
                is_fiscal_year=form.is_fiscal_year.data
            )
            db.session.add(new_salary)
            db.session.commit()
            flash('Added new salary!')
        except IntegrityError as e:
            db.session.rollback()
            flash('Error adding new salary: {}'.format(e))
        return redirect(url_for('main.officer_profile',
                                officer_id=officer_id), code=302)
    elif current_user.is_area_coordinator and not officer.department_id == current_user.ac_department_id:
        abort(403)
    else:
        return render_template('add_edit_salary.html', form=form)


@main.route('/officer/<int:officer_id>/salary/<int:salary_id>',
            methods=['GET', 'POST'])
@login_required
@ac_or_admin_required
def edit_salary(officer_id, salary_id):
    if current_user.is_area_coordinator and not current_user.is_administrator:
        officer = Officer.query.filter_by(id=officer_id).one()
        if not ac_can_edit_officer(officer, current_user):
            abort(403)

    salary = Salary.query.filter_by(id=salary_id).one()
    form = SalaryForm(obj=salary)
    if form.validate_on_submit():
        form.populate_obj(salary)
        db.session.add(salary)
        db.session.commit()
        flash('Edited officer salary ID {}'.format(salary.id))
        return redirect(url_for('main.officer_profile', officer_id=officer_id))
    return render_template('add_edit_salary.html', form=form, update=True)


@main.route('/user/toggle/<int:uid>', methods=['POST'])
@login_required
@admin_required
def toggle_user(uid):
    try:
        user = User.query.filter_by(id=uid).one()
        if user.is_disabled:
            user.is_disabled = False
        elif not user.is_disabled:
            user.is_disabled = True
        db.session.commit()
        flash('Updated user status')
    except NoResultFound:
        flash('Unknown error occurred')
    return redirect(url_for('main.profile', username=user.username))


@main.route('/image/<int:image_id>')
@login_required
def display_submission(image_id):
    try:
        image = Image.query.filter_by(id=image_id).one()
        proper_path = serve_image(image.filepath)
    except NoResultFound:
        abort(404)
    return render_template('image.html', image=image, path=proper_path)


@main.route('/tag/<int:tag_id>')
@login_required
def display_tag(tag_id):
    try:
        tag = Face.query.filter_by(id=tag_id).one()
        proper_path = serve_image(tag.image.filepath)
    except NoResultFound:
        abort(404)
    return render_template('tag.html', face=tag, path=proper_path)


@main.route('/image/classify/<int:image_id>/<int:contains_cops>',
            methods=['POST'])
@login_required
def classify_submission(image_id, contains_cops):
    try:
        image = Image.query.filter_by(id=image_id).one()
        image.user_id = current_user.id
        if contains_cops == 1:
            image.contains_cops = True
        elif contains_cops == 0:
            image.contains_cops = False
        db.session.commit()
        flash('Updated image classification')
    except:  # noqa
        flash('Unknown error occurred')
        exception_type, value, full_tback = sys.exc_info()
        current_app.logger.error('Error classifying image: {}'.format(
            ' '.join([str(exception_type), str(value),
                      format_exc()])
        ))
    return redirect(redirect_url())
    # return redirect(url_for('main.display_submission', image_id=image_id))


@main.route('/department/new', methods=['GET', 'POST'])
@login_required
@admin_required
def add_department():
    jsloads = ['js/jquery-ui.min.js', 'js/deptRanks.js']
    form = DepartmentForm()
    if form.validate_on_submit():
        departments = [x[0] for x in db.session.query(Department.name).all()]

        if form.name.data not in departments:
            department = Department(name=form.name.data,
                                    short_name=form.short_name.data)
            db.session.add(department)
            db.session.flush()
            db.session.add(Job(
                job_title='Not Sure',
                order=0,
                department_id=department.id
            ))
            db.session.flush()
            if form.jobs.data:
                order = 1
                for job in form.data['jobs']:
                    if job:
                        db.session.add(Job(
                            job_title=job,
                            order=order,
                            is_sworn_officer=True,
                            department_id=department.id
                        ))
                        order += 1
                db.session.commit()
            flash('New department {} added to OpenOversight'.format(department.name))
        else:
            flash('Department {} already exists'.format(form.name.data))
        return redirect(url_for('main.get_started_labeling'))
    else:
        return render_template('add_edit_department.html', form=form, jsloads=jsloads)


@main.route('/department/<int:department_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_department(department_id):
    jsloads = ['js/jquery-ui.min.js', 'js/deptRanks.js']
    department = Department.query.get_or_404(department_id)
    previous_name = department.name
    form = EditDepartmentForm(obj=department)
    if form.validate_on_submit():
        new_name = form.name.data
        if new_name != previous_name:
            if Department.query.filter_by(name=new_name).count() > 0:
                flash('Department {} already exists'.format(new_name))
                return redirect(url_for('main.edit_department',
                                        department_id=department_id))
        department.name = new_name
        department.short_name = form.short_name.data
        db.session.flush()
        if form.jobs.data:
            current_ranks = Job.query.filter_by(
                department_id=department_id,
                is_sworn_officer=True
            ).filter(Job.job_title != 'Not Sure').all()
            new_ranks = []
            order = 1
            for rank in form.data['jobs']:
                if rank:
                    new_ranks.append((rank, order))
                    order += 1
            for rank in current_ranks:
                rank.order = None
                rank.is_sworn_officer = False
            for (new_rank, order) in new_ranks:
                existing_rank = Job.query.filter_by(department_id=department_id, job_title=new_rank).one_or_none()
                if existing_rank:
                    existing_rank.is_sworn_officer = True
                    existing_rank.order = order
                else:
                    db.session.add(Job(
                        job_title=new_rank,
                        order=order,
                        is_sworn_officer=True,
                        department_id=department_id
                    ))
            db.session.commit()

            # Prune any jobs from department that aren't referenced by any current officers
            query = text("DELETE FROM jobs WHERE department_id = :department_id AND is_sworn_officer = False AND NOT EXISTS (SELECT 1 FROM assignments WHERE assignments.job_id = jobs.id)")
            query = query.bindparams(department_id=department_id)
            db.session.execute(query)
        flash('Department {} edited'.format(department.name))
        return redirect(url_for('main.list_officer', department_id=department.id))
    else:
        return render_template('add_edit_department.html', form=form, update=True, jsloads=jsloads)


@main.route('/department/<int:department_id>')
def list_officer(department_id, page=1, race=[], gender=[], rank=[], min_age='16', max_age='100', name=None, badge=None, unique_internal_identifier=None):
    form = BrowseForm()
    form.rank.query = Job.query.filter_by(department_id=department_id, is_sworn_officer=True).order_by(Job.order.asc()).all()
    form_data = form.data
    form_data['race'] = race
    form_data['gender'] = gender
    form_data['rank'] = rank
    form_data['min_age'] = min_age
    form_data['max_age'] = max_age
    form_data['name'] = name
    form_data['badge'] = badge
    form_data['unique_internal_identifier'] = unique_internal_identifier

    OFFICERS_PER_PAGE = int(current_app.config['OFFICERS_PER_PAGE'])
    department = Department.query.filter_by(id=department_id).first()
    if not department:
        abort(404)
    if not department.is_active and (current_user.is_anonymous or not (current_user.is_administrator or (current_user.is_area_coordinator and current_user.ac_department_id == department_id))):
        abort(403)

    # Set form data based on URL
    if request.args.get('min_age') and request.args.get('min_age') in [ac[0] for ac in AGE_CHOICES]:
        form_data['min_age'] = request.args.get('min_age')
    if request.args.get('max_age') and request.args.get('max_age') in [ac[0] for ac in AGE_CHOICES]:
        form_data['max_age'] = request.args.get('max_age')
    if request.args.get('page'):
        page = int(request.args.get('page'))
    if request.args.get('name'):
        form_data['name'] = request.args.get('name')
    if request.args.get('badge'):
        form_data['badge'] = request.args.get('badge')
    if request.args.get('unique_internal_identifier'):
        form_data['unique_internal_identifier'] = request.args.get('unique_internal_identifier')
    if request.args.get('race') and all(race in [rc[0] for rc in RACE_CHOICES] for race in request.args.getlist('race')):
        form_data['race'] = request.args.getlist('race')
    if request.args.get('gender') and all(gender in [gc[0] for gc in GENDER_CHOICES] for gender in request.args.getlist('gender')):
        form_data['gender'] = request.args.getlist('gender')

    rank_choices = [jc[0] for jc in db.session.query(Job.job_title, Job.order).filter_by(department_id=department_id, is_sworn_officer=True).order_by(Job.order).all()]
    if request.args.get('rank') and all(rank in rank_choices for rank in request.args.getlist('rank')):
        form_data['rank'] = request.args.getlist('rank')

    officers = filter_by_form(form_data, Officer.query, department_id).filter(Officer.department_id == department_id).order_by(Officer.last_name).paginate(page, OFFICERS_PER_PAGE, False)

    choices = {
        'race': RACE_CHOICES,
        'gender': GENDER_CHOICES,
        'rank': [(rc, rc) for rc in rank_choices]
    }

    return render_template(
        'list_officer.html',
        form=form,
        department=department,
        officers=officers,
        form_data=form_data,
        choices=choices)


@main.route('/department/<int:department_id>/ranks')
@main.route('/ranks')
def get_dept_ranks(department_id=None, is_sworn_officer=None):
    if not department_id:
        department_id = request.args.get('department_id')
    if request.args.get('is_sworn_officer'):
        is_sworn_officer = request.args.get('is_sworn_officer')

    if department_id:
        department = Department.query.filter_by(id=department_id).one()
        if not department.is_active and (current_user.is_anonymous or not (current_user.is_administrator or current_user.ac_department_id == department_id)):
            abort(403)
        ranks = Job.query.filter_by(department_id=department_id)
        if is_sworn_officer:
            ranks = ranks.filter_by(is_sworn_officer=True)
        ranks = ranks.order_by(Job.order.asc()).all()
        rank_list = [(rank.id, rank.job_title) for rank in ranks]
    else:
        ranks = Job.query.all()  # Not filtering by is_sworn_officer
        rank_list = list(set([(rank.id, rank.job_title) for rank in ranks]))  # Prevent duplicate ranks

    return jsonify(rank_list)


@main.route('/officer/new', methods=['GET', 'POST'])
@login_required
@ac_or_admin_required
def add_officer():
    jsloads = ['js/dynamic_lists.js', 'js/add_officer.js']
    form = AddOfficerForm()
    for link in form.links:
        link.user_id.data = current_user.id
    add_unit_query(form, current_user)
    add_department_query(form, current_user)
    set_dynamic_default(form.department, current_user.dept_pref_rel)

    if form.validate_on_submit() and not current_user.is_administrator and form.department.data.id != current_user.ac_department_id:
            abort(403)
    if form.validate_on_submit():
        # Work around for WTForms limitation with boolean fields in FieldList
        new_formdata = request.form.copy()
        for key in new_formdata.keys():
            if re.fullmatch(r'salaries-\d+-is_fiscal_year', key):
                new_formdata[key] = 'y'
        form = AddOfficerForm(new_formdata)
        officer = add_officer_profile(form, current_user)
        flash('New Officer {} added to OpenOversight'.format(officer.last_name))
        return redirect(url_for('main.officer_profile', officer_id=officer.id))
    else:
        return render_template('add_officer.html', form=form, jsloads=jsloads)


@main.route('/officer/<int:officer_id>/edit', methods=['GET', 'POST'])
@login_required
@ac_or_admin_required
def edit_officer(officer_id):
    jsloads = ['js/dynamic_lists.js']
    officer = Officer.query.filter_by(id=officer_id).one()
    form = EditOfficerForm(obj=officer)
    for link in form.links:
        if not link.user_id.data:
            link.user_id.data = current_user.id

    if current_user.is_area_coordinator and not current_user.is_administrator:
        if not ac_can_edit_officer(officer, current_user):
            abort(403)

    add_department_query(form, current_user)

    if form.validate_on_submit():
        officer = edit_officer_profile(officer, form)
        flash('Officer {} edited'.format(officer.last_name))
        return redirect(url_for('main.officer_profile', officer_id=officer.id))
    else:
        return render_template('edit_officer.html', form=form, jsloads=jsloads)


@main.route('/unit/new', methods=['GET', 'POST'])
@login_required
@ac_or_admin_required
def add_unit():
    form = AddUnitForm()
    add_department_query(form, current_user)
    set_dynamic_default(form.department, current_user.dept_pref_rel)

    if form.validate_on_submit():
        unit = Unit(descrip=form.descrip.data,
                    department_id=form.department.data.id)
        db.session.add(unit)
        db.session.commit()
        flash('New unit {} added to OpenOversight'.format(unit.descrip))
        return redirect(url_for('main.get_started_labeling'))
    else:
        return render_template('add_unit.html', form=form)


@main.route('/tag/delete/<int:tag_id>', methods=['POST'])
@login_required
@ac_or_admin_required
def delete_tag(tag_id):
    tag = Face.query.filter_by(id=tag_id).first()

    if not tag:
        flash('Tag not found')
        return redirect(url_for('main.index'))

    if not current_user.is_administrator and current_user.is_area_coordinator:
        if current_user.ac_department_id != tag.officer.department_id:
            abort(403)

    try:
        db.session.delete(tag)
        db.session.commit()
        flash('Deleted this tag')
    except:  # noqa
        flash('Unknown error occurred')
        exception_type, value, full_tback = sys.exc_info()
        current_app.logger.error('Error classifying image: {}'.format(
            ' '.join([str(exception_type), str(value),
                      format_exc()])
        ))
    return redirect(url_for('main.index'))


@main.route('/leaderboard')
@login_required
def leaderboard():
    top_sorters, top_taggers = compute_leaderboard_stats()
    return render_template('leaderboard.html', top_sorters=top_sorters,
                           top_taggers=top_taggers)


@main.route('/cop_face/department/<int:department_id>/image/<int:image_id>',
            methods=['GET', 'POST'])
@main.route('/cop_face/image/<int:image_id>', methods=['GET', 'POST'])
@main.route('/cop_face/department/<int:department_id>', methods=['GET', 'POST'])
@main.route('/cop_face/', methods=['GET', 'POST'])
@login_required
def label_data(department_id=None, image_id=None):
    jsloads = ['js/cropper.js', 'js/tagger.js']
    if department_id:
        department = Department.query.filter_by(id=department_id).one_or_none()
        if not department:
            abort(404)
        if not department.is_active and not (current_user.is_administrator or (current_user.is_area_coordinator and current_user.ac_department_id == department_id)):
            abort(403)
        if image_id:
            image = Image.query.filter_by(id=image_id) \
                               .filter_by(department_id=department_id).one()
        else:  # Get a random image from that department
            image_query = Image.query.filter_by(contains_cops=True) \
                               .filter_by(department_id=department_id) \
                               .filter_by(is_tagged=False)
            image = get_random_image(image_query)
    else:
        department = None
        if image_id:
            image = Image.query.filter_by(id=image_id).one()
        else:  # Select a random untagged image from an active department
            image = get_random_image_from_active_department()

    if image:
        proper_path = serve_image(image.filepath)
    else:
        proper_path = None

    form = FaceTag()
    if form.validate_on_submit():
        officer_exists = Officer.query.filter_by(id=form.officer_id.data).first()
        existing_tag = db.session.query(Face) \
                         .filter(Face.officer_id == form.officer_id.data) \
                         .filter(Face.img_id == form.image_id.data).first()
        if not officer_exists:
            flash('Invalid officer ID. Please select a valid OpenOversight ID!')
        elif not existing_tag:
            left = form.dataX.data
            upper = form.dataY.data
            right = left + form.dataWidth.data
            lower = upper + form.dataHeight.data
            cropped_image = get_uploaded_cropped_image(image, (left, upper, right, lower))

            if cropped_image:
                new_tag = Face(officer_id=form.officer_id.data,
                               img_id=cropped_image.id,
                               original_image_id=image.id,
                               face_position_x=left,
                               face_position_y=upper,
                               face_width=form.dataWidth.data,
                               face_height=form.dataHeight.data,
                               user_id=current_user.id)
                db.session.add(new_tag)
                db.session.commit()
                flash('Tag added to database')
            else:
                flash('There was a problem saving this tag. Please try again later.')
        else:
            flash('Tag already exists between this officer and image! Tag not added.')

    return render_template('cop_face.html', form=form,
                           image=image, path=proper_path,
                           department=department, jsloads=jsloads)


@main.route('/image/tagged/<int:image_id>')
@login_required
def complete_tagging(image_id):
    # Select a random untagged image from the database
    image = Image.query.filter_by(id=image_id).first()
    if not image:
        abort(404)
    image.is_tagged = True
    db.session.commit()
    flash('Marked image as completed.')
    department_id = request.args.get('department_id')
    if department_id:
        return redirect(url_for('main.label_data', department_id=department_id))
    else:
        return redirect(url_for('main.label_data'))


@main.route('/tagger_gallery/<int:page>', methods=['GET', 'POST'])
@main.route('/tagger_gallery', methods=['GET', 'POST'])
def get_tagger_gallery(page=1):
    if not current_user.is_anonymous and current_user.is_administrator:
        form = FindOfficerIDFormAdmin()
    else:
        form = FindOfficerForm()
    if form.validate_on_submit():
        OFFICERS_PER_PAGE = int(current_app.config['OFFICERS_PER_PAGE'])
        form_data = form.data
        officers = roster_lookup(form_data).paginate(page, OFFICERS_PER_PAGE, False)
        return render_template('tagger_gallery.html',
                               officers=officers,
                               form=form,
                               form_data=form_data)
    else:
        return redirect(url_for('main.get_ooid'), code=307)


@main.route('/complaint', methods=['GET', 'POST'])
def submit_complaint():
    return render_template('complaint.html',
                           officer_first_name=request.args.get('officer_first_name'),
                           officer_last_name=request.args.get('officer_last_name'),
                           officer_middle_initial=request.args.get('officer_middle_name'),
                           officer_star=request.args.get('officer_star'),
                           officer_image=request.args.get('officer_image'))


@main.route('/submit', methods=['GET', 'POST'])
@limiter.limit('5/minute')
def submit_data():
    if current_user.is_anonymous:
        preferred_dept_id = Department.query.first().id
        form = AddImageForm()
    else:
        preferred_dept_id = Department.query.first().id if not current_user.dept_pref else current_user.dept_pref
        if current_user.is_administrator:
            form = AddImageFormAdmin()
        else:
            form = AddImageForm()
    return render_template('submit_image.html', form=form, preferred_dept_id=preferred_dept_id)


def check_input(str_input):
    if str_input is None or str_input == "Not Sure":
        return ""
    else:
        return str(str_input).replace(",", " ")  # no commas allowed


@main.route('/download/department/<int:department_id>', methods=['GET'])
@limiter.limit('5/minute')
def download_dept_csv(department_id):
    department = Department.query.filter_by(id=department_id).first()
    records = Officer.query.filter_by(department_id=department_id).all()
    if not department or not records:
        abort(404)
    dept_name = records[0].department.name.replace(" ", "_")
    first_row = "id, last, first, middle, suffix, gender, "\
                "race, born, employment_date, assignments\n"

    assign_dict = {}
    assign_records = Assignment.query.all()
    for r in assign_records:
        if r.officer_id not in assign_dict:
            assign_dict[r.officer_id] = []
        assign_dict[r.officer_id].append("(#%s %s %s %s %s)" % (check_input(r.star_no), check_input(r.job_id), check_input(r.unit_id), check_input(r.star_date), check_input(r.resign_date)))

    record_list = ["%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" %
                   (str(record.id),
                    check_input(record.last_name),
                    check_input(record.first_name),
                    check_input(record.middle_initial),
                    check_input(record.suffix),
                    check_input(record.gender),
                    check_input(record.race),
                    check_input(record.birth_year),
                    check_input(record.employment_date),
                    " ".join(assign_dict.get(record.id, [])),
                    ) for record in records]

    csv_name = dept_name + "_Officers.csv"
    csv = first_row + "".join(record_list)
    csv_headers = {"Content-disposition": "attachment; filename=" + csv_name}
    return Response(csv, mimetype="text/csv", headers=csv_headers)


@main.route('/download/department/<int:department_id>/incidents', methods=['GET'])
@limiter.limit('5/minute')
def download_incidents_csv(department_id):
    department = Department.query.filter_by(id=department_id).first()
    records = Incident.query.filter_by(department_id=department.id).all()
    if not department or not records:
        abort(404)
    dept_name = records[0].department.name.replace(" ", "_")
    first_row = "id,report_num,date,time,description,location,licences,links,officers\n"

    record_list = ["%s,%s,%s,%s,%s,%s,%s,%s,%s\n" %
                   (str(record.id),
                    check_input(record.report_number),
                    check_input(record.date),
                    check_input(record.time),
                    check_input(record.description),
                    check_input(record.address),
                    " ".join(map(lambda x: str(x), record.license_plates)),
                    " ".join(map(lambda x: str(x), record.links)),
                    " ".join(map(lambda x: str(x), record.officers)),
                    ) for record in records]

    csv_name = dept_name + "_Incidents.csv"
    csv = first_row + "".join(record_list)
    csv_headers = {"Content-disposition": "attachment; filename=" + csv_name}
    return Response(csv, mimetype="text/csv", headers=csv_headers)


@main.route('/download/all', methods=['GET'])
def all_data():
    departments = Department.query.all()
    return render_template('all_depts.html', departments=departments)


@main.route('/upload/department/<int:department_id>', methods=['POST'])
@limiter.limit('250/minute')
def upload(department_id):
    file_to_upload = request.files['file']
    if not allowed_file(file_to_upload.filename):
        return jsonify(error="File type not allowed!"), 415
    original_filename = secure_filename(file_to_upload.filename)
    image_data = file_to_upload.read()

    # See if there is a matching photo already in the db
    hash_img = compute_hash(image_data)
    hash_found = Image.query.filter_by(hash_img=hash_img).first()
    if hash_found:
        return jsonify(error="Image already uploaded to OpenOversight!"), 400

    # Generate new filename
    file_extension = original_filename.split('.')[-1]
    new_filename = '{}.{}'.format(hash_img, file_extension)

    # Save temporarily on local filesystem
    tmpdir = tempfile.mkdtemp()
    safe_local_path = os.path.join(tmpdir, new_filename)
    with open(safe_local_path, 'wb') as tmp:
        tmp.write(image_data)
    os.umask(SAVED_UMASK)

    # Upload file from local filesystem to S3 bucket and delete locally
    try:
        url = upload_file(safe_local_path, original_filename,
                          new_filename)
        # Update the database to add the image
        try:
            new_image = Image(filepath=url, hash_img=hash_img, is_tagged=False,
                              date_image_inserted=datetime.datetime.now(),
                              department_id=department_id,
                              # TODO: Get the following field from exif data
                              date_image_taken=datetime.datetime.now(),
                              user_id=current_user.id)
        except AttributeError:
            new_image = Image(filepath=url, hash_img=hash_img, is_tagged=False,
                              date_image_inserted=datetime.datetime.now(),
                              department_id=department_id,
                              # TODO: Get the following field from exif data
                              date_image_taken=datetime.datetime.now())
        db.session.add(new_image)
        db.session.commit()
        return jsonify(success="Success!"), 200
    except:  # noqa
        exception_type, value, full_tback = sys.exc_info()
        current_app.logger.error('Error uploading to S3: {}'.format(
            ' '.join([str(exception_type), str(value),
                      format_exc()])
        ))
        return jsonify(error="Server error encountered. Try again later."), 500
    os.remove(safe_local_path)
    os.rmdir(tmpdir)


@main.route('/about')
def about_oo():
    return render_template('about.html')


@main.route('/privacy')
def privacy_oo():
    return render_template('privacy.html')


@main.route('/shutdown')    # pragma: no cover
def server_shutdown():      # pragma: no cover
    if not current_app.testing:
        abort(404)
    shutdown = request.environ.get('werkzeug.server.shutdown')
    if not shutdown:
        abort(500)
    shutdown()
    return 'Shutting down...'


@main.route('/departments/ac_department', methods=['GET', 'POST'])
@login_required
@ac_or_admin_required
def view_ac_dept():
    dept_id = current_user.ac_department_id
    dept = Department.query.filter_by(id=dept_id).first()
    form = ChangeDepartmentStatusForm(is_active=dept.is_active)
    if form.validate_on_submit():
        dept.is_active = form.data['is_active']
        db.session.add(dept)
        db.session.commit()
        flash("Updated!")
        return redirect(url_for('main.view_ac_dept'))

    return render_template('department.html', department=dept, form=form)


class DepartmentAPI(MethodView):
    decorators = [admin_required]

    def get(self, department_id):
        # isolate the last part of the url
        end_of_url = request.url.split('/')[-1].split('?')[0]

        def find_area_coords(department_id):
            area_coords = db.session.query(Department, User).filter(department_id == User.ac_department_id).all()
            for ac in area_coords:
                return {"id": ac[1].id, "username": ac[1].username}

        def display_dept_status(department):
            if department.is_active:
                return "Active"
            else:
                return "Inactive"

        if department_id is None:
            departments = Department.query.order_by(Department.name).all()
            return render_template('departments.html', departments=departments, find_area_coords=find_area_coords, display_dept_status=display_dept_status)
        else:
            dept = Department.query.get(department_id)
            if not dept:
                return render_template('403.html'), 403
            actions = ['delete', 'enable', 'disable']
            if end_of_url in actions:
                action = getattr(self, end_of_url, None)
                return action(dept)
            else:
                form = EditDepartmentForm(name=dept.name, short_name=dept.short_name, is_active=dept.is_active)
                return render_template('department.html', department=dept, form=form)

    def post(self, department_id):
        end_of_url = request.url.split('/')[-1].split('?')[0]

        department = Department.query.get(department_id)
        form = EditDepartmentForm()

        if department and end_of_url and end_of_url == 'delete':
            return self.delete(department)
        elif department and form.validate_on_submit():
            new_name = form.name.data
            if new_name != department.name:
                if Department.query.filter_by(name=new_name).count() > 0:
                    flash('{} already exists'.format(new_name))
                    return render_template('department.html', department=department, form=form)
            for field, data in iteritems(form.data):
                setattr(department, field, data)
            db.session.add(department)
            db.session.commit()
            flash('{} has been updated!'.format(department.name))
            return redirect(url_for('main.department_api'))
        elif not form.validate_on_submit():
            flash('Invalid entry')
            return render_template('department.html', department=department, form=form)
        else:
            return render_template('403.html'), 403

    def enable(self, department):
        if department.is_active:
            flash('{} is already enabled.'.format(department.name))
        else:
            department.is_active = True
            db.session.add(department)
            db.session.commit()
            flash('{} has been enabled!'.format(department.name))
        return redirect(url_for('main.department_api'))

    def disable(self, department):
        if not department.is_active:
            flash('{} is already disabled.'.format(department.name))
        else:
            department.is_active = False
            db.session.add(department)
            db.session.commit()
            flash('{} has been disabled!'.format(department.name))
        return redirect(url_for('main.department_api'))

    def delete(self, department):
        if request.method == 'POST':
            dept_name = department.name
            db.session.delete(department)
            db.session.commit()
            flash('{} has been deleted!'.format(dept_name))
            return redirect(url_for('main.department_api'))

        return render_template('department_delete.html', department=department)


department_view = DepartmentAPI.as_view('department_api')
main.add_url_rule(
    '/departments/',
    defaults={'department_id': None},
    view_func=department_view,
    methods=['GET'])
main.add_url_rule(
    '/departments/<int:department_id>',
    view_func=department_view,
    methods=['GET', 'POST'])
main.add_url_rule(
    '/departments/<int:department_id>/edit',
    view_func=department_view,
    methods=['GET', 'POST'])
main.add_url_rule(
    '/departments/<int:department_id>/delete',
    view_func=department_view,
    methods=['GET', 'POST'])
main.add_url_rule(
    '/departments/<int:department_id>/enable',
    view_func=department_view,
    methods=['GET'])
main.add_url_rule(
    '/departments/<int:department_id>/disable',
    view_func=department_view,
    methods=['GET'])


class IncidentApi(ModelView):
    model = Incident
    model_name = 'incident'
    order_by = 'date'
    descending = True
    form = IncidentForm
    create_function = create_incident
    department_check = True

    def get(self, obj_id):
        if request.args.get('page'):
            page = int(request.args.get('page'))
        else:
            page = 1
        if request.args.get('department_id'):
            department_id = int(request.args.get('department_id'))
            dept = Department.query.get_or_404(department_id)
            incidents = Incident.query\
                .filter_by(department_id=department_id)\
                .order_by(getattr(self.model, self.order_by).desc())\
                .paginate(page, self.per_page, False)
            if not dept.is_active and current_user.is_anonymous:
                abort(403)
            if not dept.is_active and not (current_user.is_administrator or current_user.ac_department_id == department_id):
                abort(403)
            return render_template('incident_list.html', objects=incidents, url='main.incident_api', department=dept)
        else:
            if obj_id is None:
                if current_user.is_anonymous:
                    incidents = Incident.query\
                                        .join(Incident.department)\
                                        .filter(Department.is_active == true())\
                                        .order_by(getattr(self.model, self.order_by).desc())\
                                        .paginate(page, self.per_page, False)
                else:
                    if current_user.is_administrator:
                        incidents = Incident.query\
                                            .order_by(getattr(self.model, self.order_by).desc())\
                                            .paginate(page, self.per_page, False)
                    if current_user.is_area_coordinator:
                        incidents = Incident.query\
                                            .join(Incident.department)\
                                            .filter(or_(Department.is_active == true(), Department.id == current_user.ac_department_id))\
                                            .order_by(getattr(self.model, self.order_by).desc())\
                                            .paginate(page, self.per_page, False)
                    if not (current_user.is_administrator or current_user.is_area_coordinator):
                        incidents = Incident.query\
                                            .join(Incident.department)\
                                            .filter(Department.is_active == true())\
                                            .order_by(getattr(self.model, self.order_by).desc())\
                                            .paginate(page, self.per_page, False)
                return render_template('incident_list.html', objects=incidents, url='main.incident_api')
            else:
                incident = Incident.query.get_or_404(obj_id)
                dept = Department.query.filter_by(id=incident.department_id).one()
                if not dept.is_active:
                    if current_user.is_anonymous:
                        abort(403)
                    if not current_user.is_administrator and current_user.ac_department_id != self.get_department_id(incident):
                        abort(403)
                return render_template('incident_detail.html', obj=incident, current_user=current_user)

    def get_new_form(self):
        form = self.form()
        if request.args.get('officer_id'):
            form.officers[0].oo_id.data = request.args.get('officer_id')

        for link in form.links:
            link.user_id.data = current_user.id
        return form

    def get_edit_form(self, obj):
        form = super(IncidentApi, self).get_edit_form(obj=obj)

        no_license_plates = len(obj.license_plates)
        no_links = len(obj.links)
        no_officers = len(obj.officers)
        for link in form.links:
            if link.user_id.data:
                continue
            else:
                link.user_id.data = current_user.id

        for officer_idx, officer in enumerate(obj.officers):
            form.officers[officer_idx].oo_id.data = officer.id

        # set the form to have fields for all the current model's items
        form.license_plates.min_entries = no_license_plates
        form.links.min_entries = no_links
        form.officers.min_entries = no_officers
        if not form.date_field.data and obj.date:
            form.date_field.data = obj.date
        if not form.time_field.data and obj.time:
            form.time_field.data = obj.time
        return form

    def populate_obj(self, form, obj):
        # remove all fields not directly on the Incident model
        # use utils to add them to the current object
        address = form.data.pop('address')
        del form.address
        if address['city']:
            new_address, _ = get_or_create(db.session, Location, **address)
            obj.address = new_address
        else:
            obj.address = None

        links = form.data.pop('links')
        del form.links
        if links and links[0]['url']:
            replace_list(links, obj, 'links', Link, db)

        officers = form.data.pop('officers')
        del form.officers
        if officers:
            for officer in officers:
                if officer["oo_id"]:
                    try:
                        of = Officer.query.filter_by(id=int(officer["oo_id"])).first()
                    # Sometimes we get a string in officer["oo_id"], this parses it
                    except ValueError:
                        our_id = officer["oo_id"].split("value=\"")[1][:-2]
                        of = Officer.query.filter_by(id=int(our_id)).first()
                    if of:
                        obj.officers.append(of)

        license_plates = form.data.pop('license_plates')
        del form.license_plates
        if license_plates and license_plates[0]['number']:
            replace_list(license_plates, obj, 'license_plates', LicensePlate, db)

        obj.date = form.date_field.data
        if form.time_field.raw_data and form.time_field.raw_data != ['']:
            obj.time = form.time_field.data
        else:
            obj.time = None
        super(IncidentApi, self).populate_obj(form, obj)


incident_view = IncidentApi.as_view('incident_api')
main.add_url_rule(
    '/incidents/',
    defaults={'obj_id': None},
    view_func=incident_view,
    methods=['GET'])
main.add_url_rule(
    '/incidents/new',
    view_func=incident_view,
    methods=['GET', 'POST'])
main.add_url_rule(
    '/incidents/<int:obj_id>',
    view_func=incident_view,
    methods=['GET'])
main.add_url_rule(
    '/incidents/<int:obj_id>/edit',
    view_func=incident_view,
    methods=['GET', 'POST'])
main.add_url_rule(
    '/incidents/<int:obj_id>/delete',
    view_func=incident_view,
    methods=['GET', 'POST'])


class TextApi(ModelView):
    order_by = 'date_created'
    descending = True
    department_check = True
    form = TextForm

    def get_new_form(self):
        form = self.form()
        form.officer_id.data = self.officer_id
        return form

    def get_redirect_url(self, *args, **kwargs):
        return redirect(url_for('main.officer_profile', officer_id=self.officer_id))

    def get_post_delete_url(self, *args, **kwargs):
        return self.get_redirect_url()

    def get_department_id(self, obj):
        return self.department_id

    def get_edit_form(self, obj):
        form = EditTextForm(obj=obj)
        return form

    def dispatch_request(self, *args, **kwargs):
        if 'officer_id' in kwargs:
            officer = Officer.query.get_or_404(kwargs['officer_id'])
            self.officer_id = kwargs.pop('officer_id')
            self.department_id = officer.department_id
        return super(TextApi, self).dispatch_request(*args, **kwargs)


class NoteApi(TextApi):
    model = Note
    model_name = 'note'
    form = TextForm
    create_function = create_note

    def dispatch_request(self, *args, **kwargs):
        return super(NoteApi, self).dispatch_request(*args, **kwargs)


class DescriptionApi(TextApi):
    model = Description
    model_name = 'description'
    form = TextForm
    create_function = create_description

    def dispatch_request(self, *args, **kwargs):
        return super(DescriptionApi, self).dispatch_request(*args, **kwargs)


note_view = NoteApi.as_view('note_api')
main.add_url_rule(
    '/officer/<int:officer_id>/note/new',
    view_func=note_view,
    methods=['GET', 'POST'])
main.add_url_rule(
    '/officer/<int:officer_id>/note/<int:obj_id>',
    view_func=note_view,
    methods=['GET'])
main.add_url_rule(
    '/officer/<int:officer_id>/note/<int:obj_id>/edit',
    view_func=note_view,
    methods=['GET', 'POST'])
main.add_url_rule(
    '/officer/<int:officer_id>/note/<int:obj_id>/delete',
    view_func=note_view,
    methods=['GET', 'POST'])

description_view = DescriptionApi.as_view('description_api')
main.add_url_rule(
    '/officer/<int:officer_id>/description/new',
    view_func=description_view,
    methods=['GET', 'POST'])
main.add_url_rule(
    '/officer/<int:officer_id>/description/<int:obj_id>',
    view_func=description_view,
    methods=['GET'])
main.add_url_rule(
    '/officer/<int:officer_id>/description/<int:obj_id>/edit',
    view_func=description_view,
    methods=['GET', 'POST'])
main.add_url_rule(
    '/officer/<int:officer_id>/description/<int:obj_id>/delete',
    view_func=description_view,
    methods=['GET', 'POST'])
