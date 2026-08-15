"""Training progress survives being promoted to staff and demoted back.

    venv/bin/python tests/test_promotion_keeps_progress.py

Promotion keeps the member's own row and turns it into the admin mirror, so
everything hanging off it stays attached.

Demotion picks one mirror to become their account again and deletes the others.
It used to pick by location — the site the admin was viewing, else the lowest
website_id — and promotion has by then created an empty mirror on every site.
On a single-site install there is only one mirror so it is always right. On a
multi-site install, a member of a SECONDARY site demoted from the primary got
the empty mirror kept and their real row deleted:

    learner, before : progress 1, attempts 1, ksa 1, divisions 1, threads 1
    demote          : 200
    after           : progress 0, attempts 0, ksa 0, divisions 0, threads 0

Nullable links (guide progress, quiz attempts) were set to NULL and not-null
ones (KSA levels, division memberships) deleted outright, so the training
record was simply gone.

The survivor is now chosen by which mirror actually carries the history, and
any other mirror that has history of its own is detached into an ordinary
member account rather than deleted.

Copies main.py into a throwaway directory and imports it from there, so it
builds its own SQLite database and cannot touch the real instance.
"""
import atexit
import os
import shutil
import sys
import tempfile

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-progress-survival')
os.environ.setdefault('UWEBIA_COOKIE_SECURE', '0')

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRATCH = tempfile.mkdtemp(prefix='uwebia-progress-test-')
# Each of these holds a ~2.5 MB copy of main.py and a SQLite database; nothing
# removed them, so repeated suite runs left GBs behind in /tmp.
atexit.register(shutil.rmtree, _SCRATCH, ignore_errors=True)
shutil.copy2(os.path.join(_REPO, 'main.py'), os.path.join(_SCRATCH, 'main.py'))
for _linked in ('Templates', 'icons', 'static'):
    _src = os.path.join(_REPO, _linked)
    if os.path.exists(_src):
        os.symlink(_src, os.path.join(_SCRATCH, _linked))

sys.path.insert(0, _SCRATCH)
import main  # noqa: E402

assert os.path.dirname(os.path.abspath(main.__file__)) == _SCRATCH, \
    'refusing to run against the real checkout'

app, db = main.app, main.db
FAILURES = []


def check(label, cond):
    print(('  PASS  ' if cond else '  FAIL  ') + label)
    if not cond:
        FAILURES.append(label)


def history(pu_id):
    """Everything a learner accumulates, counted per kind."""
    return {
        'guide progress': main.GuideProgress.query.filter_by(public_user_id=pu_id).count(),
        'quiz attempts': main.QuizAttempt.query.filter_by(public_user_id=pu_id).count(),
        'KSA levels': main.UserKSA.query.filter_by(public_user_id=pu_id).count(),
        'divisions': main.DivisionMembership.query.filter_by(public_user_id=pu_id).count(),
        'forum threads': main.ForumThread.query.filter_by(public_user_id=pu_id).count(),
    }


def build(second_site):
    """A learner with a full history. `second_site` adds a site they are NOT on.

    That decoy is deliberately the PRIMARY site — no url_prefix, created first
    so it also holds the lower id. Both of those matter, because the old
    survivor rule was "the mirror on the site the admin is viewing, else the
    lowest website_id", and get_admin_website() itself falls back to the
    primary. Put the learner on the primary and every one of those fallbacks
    picks the right mirror by luck; put them on a secondary site and they all
    pick the empty one.
    """
    with app.app_context():
        db.create_all()
        db.session.remove()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()

        owner = main.User(username='owner', parent_user_id=None)
        owner.set_password('x')
        db.session.add(owner)
        db.session.commit()

        other_id = None
        if second_site:
            other = main.Website(user_id=owner.id, name='Other', is_draft=False)
            db.session.add(other)
            db.session.commit()
            other_id = other.id

        home = main.Website(user_id=owner.id, name='Learners', is_draft=False,
                            url_prefix='learners' if second_site else None)
        db.session.add(home)
        db.session.commit()

        guide = main.Guide(website_id=home.id, title='Robotics', slug='robotics',
                           status='published')
        quiz = main.Quiz(website_id=home.id, title='Safety')
        division = main.Division(website_id=home.id, name='Build', slug='build')
        db.session.add_all([guide, quiz, division])
        db.session.commit()
        node = main.GuideNode(guide_id=guide.id, website_id=home.id,
                              node_type='lesson', title='Wiring', slug='wiring')
        ksa = main.KSA(website_id=home.id, division_id=division.id, name='Soldering')
        db.session.add_all([node, ksa])
        db.session.commit()

        learner = main.PublicUser(website_id=home.id, username='learner')
        learner.set_password('pw12345678')
        db.session.add(learner)
        db.session.commit()
        db.session.add_all([
            main.GuideProgress(public_user_id=learner.id, guide_id=guide.id,
                               guide_node_id=node.id, website_id=home.id,
                               visitor_id_hash='h1'),
            main.QuizAttempt(public_user_id=learner.id, quiz_id=quiz.id,
                             website_id=home.id, score=90),
            main.UserKSA(public_user_id=learner.id, ksa_id=ksa.id),
            main.DivisionMembership(public_user_id=learner.id, division_id=division.id),
            main.ForumThread(website_id=home.id, public_user_id=learner.id,
                             title='Hello', body='Hi'),
        ])
        db.session.commit()
        return owner.id, home.id, other_id, learner.id


def run(label, second_site, demote_from_other_site):
    owner_id, home_id, other_id, learner_id = build(second_site)
    app.config['WTF_CSRF_ENABLED'] = False
    with app.app_context():
        before = history(learner_id)
    print(f'\n{label}')
    print(f'         before: {before}')

    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(owner_id)
        s['_fresh'] = True
        s['editing_website_id'] = home_id

    r = c.post(f'/admin/users/public/{learner_id}/promote', json={'permissions': {}})
    check(f'promotion succeeds — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        pu = db.session.get(main.PublicUser, learner_id)
        check('their own row becomes the staff mirror, keeping its id',
              pu is not None and pu.mirrored_admin_user_id is not None)
        after_promote = history(learner_id)
        check(f'nothing is lost on promotion ({after_promote})',
              after_promote == before)
        admin_id = pu.mirrored_admin_user_id

    # Demoting from a site the learner was never on is the case that used to
    # keep the wrong mirror.
    if demote_from_other_site and other_id:
        with c.session_transaction() as s:
            s['editing_website_id'] = other_id

    r = c.post(f'/admin/users/{admin_id}/demote')
    check(f'demotion succeeds — got {r.status_code}', r.status_code == 200)
    with app.app_context():
        check('their account is still the same row',
              db.session.get(main.PublicUser, learner_id) is not None)
        after = history(learner_id)
        lost = {k: (before[k], after[k]) for k in before if after[k] != before[k]}
        for k, (b, a) in lost.items():
            print(f'         LOST {k}: {b} -> {a}')
        check(f'nothing is lost on demotion ({after})', not lost)
        pu = db.session.get(main.PublicUser, learner_id)
        check('and they are an ordinary member again',
              pu is not None and pu.mirrored_admin_user_id is None)
        check('who can still sign in', bool(pu and pu.password_hash))


def main_test():
    run('[1] one website', second_site=False, demote_from_other_site=False)
    run('[2] two websites, demoted from the one they are NOT on',
        second_site=True, demote_from_other_site=True)
    run('[3] two websites, demoted from their own',
        second_site=True, demote_from_other_site=False)


if __name__ == '__main__':
    main_test()
    print('\n' + ('ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'))
    sys.exit(1 if FAILURES else 0)
