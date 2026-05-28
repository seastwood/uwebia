/* guide_quiz.js — hydrates quiz embeds on public pages.
 *
 * Scans for `.uw-quiz-embed[data-quiz-id]` (emitted by the lesson editor's quiz
 * blot and, later, by the page-builder quiz section), fetches the answer-free
 * quiz payload, renders an interactive form, grades server-side on submit, and
 * shows per-question feedback + score with unlimited retakes.
 *
 * Set `window.UW_GUIDE_NODE_ID` before this script runs to attribute attempts
 * to a lesson (used for progress context). Self-contained: injects its own CSS.
 */
(function () {
    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function injectStyles() {
        if (document.getElementById('uwq-styles')) return;
        const css = `
.uw-quiz-embed.uwq-live { display:block; padding:0; border:none; background:none; }
.uwq { border:1px solid rgba(94,238,248,0.25); border-radius:14px; padding:20px 22px; margin:22px 0; background:rgba(94,238,248,0.04); }
.uwq-head { display:flex; align-items:center; gap:10px; margin-bottom:6px; }
.uwq-head i { color:#5eeec8; }
.uwq-head h3 { margin:0; font-size:1.05rem; font-weight:800; }
.uwq-desc { opacity:0.7; font-size:0.92rem; margin:0 0 14px; }
.uwq-q { padding:14px 0; border-top:1px solid rgba(255,255,255,0.08); }
.uwq-q:first-of-type { border-top:none; }
.uwq-prompt { font-weight:600; margin:0 0 10px; display:flex; gap:8px; align-items:baseline; }
.uwq-num { display:inline-flex; align-items:center; justify-content:center; min-width:22px; height:22px; border-radius:50%; background:rgba(94,238,248,0.18); color:#5eeef8; font-size:0.75rem; font-weight:700; flex-shrink:0; }
.uwq-opt { display:flex; align-items:center; gap:9px; padding:8px 10px; border-radius:8px; cursor:pointer; transition:background 0.12s; }
.uwq-opt:hover { background:rgba(255,255,255,0.05); }
.uwq-opt input { accent-color:#5eeef8; width:16px; height:16px; }
.uwq-opt.opt-correct { background:rgba(94,238,200,0.14); }
.uwq-opt.opt-correct span::after { content:" ✓"; color:#5eeec8; font-weight:700; }
.uwq-opt.opt-chosen-wrong { background:rgba(255,90,90,0.14); }
.uwq-opt.opt-chosen-wrong span::after { content:" ✕"; color:#ff7676; font-weight:700; }
.uwq-text { width:100%; max-width:360px; padding:9px 12px; border-radius:8px; border:1px solid rgba(255,255,255,0.18); background:rgba(255,255,255,0.06); color:inherit; font-size:0.95rem; outline:none; }
.uwq-text:focus { border-color:rgba(94,238,248,0.5); }
.uwq-q.is-correct { } .uwq-q.is-wrong { }
.uwq-fb { margin-top:8px; font-size:0.84rem; opacity:0.85; }
.uwq-ok { color:#5eeec8; font-weight:700; }
.uwq-no { color:#ff7676; font-weight:700; }
.uwq-actions { display:flex; align-items:center; gap:14px; margin-top:16px; padding-top:14px; border-top:1px solid rgba(255,255,255,0.08); }
.uwq-submit { padding:9px 22px; border-radius:9px; border:none; cursor:pointer; font-weight:700; background:linear-gradient(135deg,#5eeef8,#5eeec8); color:#111; }
.uwq-submit:disabled { opacity:0.6; cursor:default; }
.uwq-score { font-size:0.9rem; font-weight:600; opacity:0.85; }
.uwq-err { padding:14px; border-radius:10px; background:rgba(255,90,90,0.1); color:#ff9b9b; font-size:0.9rem; }
.uwq-loading { padding:14px; opacity:0.5; font-size:0.9rem; }
`;
        const style = document.createElement('style');
        style.id = 'uwq-styles';
        style.textContent = css;
        document.head.appendChild(style);
    }

    async function hydrate(el) {
        const quizId = el.getAttribute('data-quiz-id');
        if (!quizId || el._uwq) return;
        el._uwq = true;
        el.classList.add('uwq-live');
        el.innerHTML = '<div class="uwq-loading">Loading quiz…</div>';
        let data;
        try { data = await (await fetch('/api/quizzes/' + quizId)).json(); }
        catch (e) { el.innerHTML = '<div class="uwq-err">Could not load quiz.</div>'; return; }
        if (!data || !data.success) { el.innerHTML = '<div class="uwq-err">Quiz unavailable.</div>'; return; }
        renderQuiz(el, data.quiz);
    }

    function renderQuiz(el, quiz) {
        let html = '<div class="uwq"><div class="uwq-head"><i class="fas fa-clipboard-check"></i><h3>' + esc(quiz.title) + '</h3></div>';
        if (quiz.description) html += '<p class="uwq-desc">' + esc(quiz.description) + '</p>';
        html += '<form class="uwq-form">';
        (quiz.questions || []).forEach((q, qi) => {
            html += '<div class="uwq-q" data-qid="' + q.id + '" data-qtype="' + q.question_type + '">';
            html += '<p class="uwq-prompt"><span class="uwq-num">' + (qi + 1) + '</span>' + esc(q.prompt) + '</p>';
            if (q.question_type === 'short_text') {
                html += '<input type="text" class="uwq-text" name="q' + q.id + '" autocomplete="off">';
            } else {
                const inputType = (q.question_type === 'multi_choice') ? 'checkbox' : 'radio';
                (q.options || []).forEach(o => {
                    html += '<label class="uwq-opt"><input type="' + inputType + '" name="q' + q.id + '" value="' + o.id + '"> <span>' + esc(o.text) + '</span></label>';
                });
            }
            html += '<div class="uwq-fb" style="display:none;"></div></div>';
        });
        html += '<div class="uwq-actions"><button type="submit" class="uwq-submit">Submit</button><span class="uwq-score"></span></div>';
        html += '</form></div>';
        el.innerHTML = html;
        el.querySelector('.uwq-form').addEventListener('submit', ev => { ev.preventDefault(); submit(el, quiz); });
    }

    function collect(el, quiz) {
        const answers = {};
        (quiz.questions || []).forEach(q => {
            const name = 'q' + q.id;
            if (q.question_type === 'short_text') {
                const inp = el.querySelector('input[name="' + name + '"]');
                answers[q.id] = inp ? inp.value : '';
            } else if (q.question_type === 'multi_choice') {
                answers[q.id] = Array.from(el.querySelectorAll('input[name="' + name + '"]:checked')).map(i => parseInt(i.value));
            } else {
                const sel = el.querySelector('input[name="' + name + '"]:checked');
                answers[q.id] = sel ? parseInt(sel.value) : null;
            }
        });
        return answers;
    }

    async function submit(el, quiz) {
        const answers = collect(el, quiz);
        const btn = el.querySelector('.uwq-submit');
        btn.disabled = true; btn.textContent = 'Checking…';
        let data;
        try {
            data = await (await fetch('/api/quizzes/' + quiz.id + '/submit', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ answers: answers, guide_node_id: window.UW_GUIDE_NODE_ID || null })
            })).json();
        } catch (e) { btn.disabled = false; btn.textContent = 'Submit'; return; }
        if (!data || !data.success) { btn.disabled = false; btn.textContent = 'Submit'; return; }
        showResults(el, quiz, data);
    }

    function showResults(el, quiz, data) {
        const byId = {};
        (data.results || []).forEach(r => { byId[r.question_id] = r; });
        (quiz.questions || []).forEach(q => {
            const qEl = el.querySelector('.uwq-q[data-qid="' + q.id + '"]');
            const r = byId[q.id];
            if (!qEl || !r) return;
            qEl.classList.remove('is-correct', 'is-wrong');
            qEl.classList.add(r.correct ? 'is-correct' : 'is-wrong');
            const correctIds = r.correct_option_ids || [];
            qEl.querySelectorAll('.uwq-opt').forEach(opt => {
                const inp = opt.querySelector('input');
                const val = parseInt(inp.value);
                opt.classList.remove('opt-correct', 'opt-chosen-wrong');
                if (correctIds.indexOf(val) >= 0) opt.classList.add('opt-correct');
                if (inp.checked && correctIds.indexOf(val) < 0) opt.classList.add('opt-chosen-wrong');
            });
            const fb = qEl.querySelector('.uwq-fb');
            if (fb) {
                fb.style.display = 'block';
                let txt = r.correct ? '<span class="uwq-ok">Correct</span>' : '<span class="uwq-no">Incorrect</span>';
                if (q.question_type === 'short_text' && !r.correct && r.accepted && r.accepted.length) {
                    txt += ' · Accepted: ' + r.accepted.map(esc).join(', ');
                }
                fb.innerHTML = txt;
            }
        });
        const scoreEl = el.querySelector('.uwq-score');
        let s = 'Score: ' + data.score + ' / ' + data.max_score;
        if (data.best_score != null) s += ' · Best: ' + data.best_score;
        scoreEl.textContent = s;
        const btn = el.querySelector('.uwq-submit');
        btn.disabled = false;
        btn.textContent = 'Retake';
        btn.type = 'button';
        btn.onclick = () => renderQuiz(el, quiz);
    }

    function init() {
        injectStyles();
        document.querySelectorAll('.uw-quiz-embed[data-quiz-id]').forEach(hydrate);
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
    window.UWQuiz = { init: init };
})();
