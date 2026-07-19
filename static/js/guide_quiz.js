/* guide_quiz.js — hydrates quiz embeds on public pages.
 *
 * Scans for `.uw-quiz-embed[data-quiz-id]` (emitted by the lesson editor's quiz
 * blot and, later, by the page-builder quiz section), fetches the answer-free
 * quiz payload, renders an interactive form, grades server-side on submit, and
 * shows per-question feedback + score with unlimited retakes.
 *
 * Question types: single_choice, multi_choice, true_false, short_text,
 * fill_blank (partial credit), matching (tap-to-place, mobile friendly),
 * ordering (move up/down), image_choice (image options), coding,
 * reflection (ungraded free writing, saved + prefilled on return),
 * flashcards (ungraded study stack with got-it / didn't-get-it sorting).
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
.uwq-fb { margin-top:8px; font-size:0.84rem; opacity:0.85; }
.uwq-ok { color:#5eeec8; font-weight:700; }
.uwq-no { color:#ff7676; font-weight:700; }
.uwq-actions { display:flex; align-items:center; gap:14px; margin-top:16px; padding-top:14px; border-top:1px solid rgba(255,255,255,0.08); flex-wrap:wrap; }
.uwq-submit { padding:9px 22px; border-radius:9px; border:none; cursor:pointer; font-weight:700; background:linear-gradient(135deg,#5eeef8,#5eeec8); color:#111; }
.uwq-submit:disabled { opacity:0.6; cursor:default; }
.uwq-score { font-size:0.9rem; font-weight:600; opacity:0.85; }
.uwq-status { padding:3px 12px; border-radius:99px; font-size:0.74rem; font-weight:800; letter-spacing:0.06em; text-transform:uppercase; }
.uwq-status.is-pass { background:rgba(94,238,200,0.18); color:#5eeec8; }
.uwq-status.is-fail { background:rgba(255,90,90,0.18); color:#ff8c8c; }
.uwq-hint { font-size:0.78rem; opacity:0.55; flex-basis:100%; margin:4px 0 0; }
.uwq-err { padding:14px; border-radius:10px; background:rgba(255,90,90,0.1); color:#ff9b9b; font-size:0.9rem; }
.uwq-loading { padding:14px; opacity:0.5; font-size:0.9rem; }
/* links + auto-embeds (any prompt / text block / description) */
.uwq a.uwq-link { color:#5eeef8; word-break:break-all; }
.uwq-embeds { display:flex; flex-direction:column; gap:10px; margin:10px 0 4px; }
.uwq-embed-frame { position:relative; width:100%; max-width:560px; aspect-ratio:16/9; }
.uwq-embed-frame iframe { position:absolute; inset:0; width:100%; height:100%; border:0; border-radius:10px; }
.uwq-embed-img { display:block; max-width:100%; max-height:320px; border-radius:10px; }
/* text block — content between questions, not a question */
.uwq-text-body { font-size:0.95rem; line-height:1.65; }
/* per-question explanation (revealed after answering) */
.uwq-expl { margin-top:7px; font-size:0.85rem; line-height:1.5; padding:7px 11px; border-left:3px solid rgba(94,238,200,0.55); background:rgba(94,238,200,0.06); border-radius:0 8px 8px 0; }
/* attempt limit / cooldown notice */
.uwq-gate { flex-basis:100%; margin:6px 0 0; padding:9px 12px; border-radius:9px; background:rgba(255,200,90,0.1); color:#ffd28a; font-size:0.85rem; }
.uwq-attempts { font-size:0.78rem; opacity:0.55; flex-basis:100%; margin:4px 0 0; }
/* locked (submitted) form — answers frozen until Retake */
.uwq-locked .uwq-opt, .uwq-locked .uwq-img-opt, .uwq-locked .uwq-chip, .uwq-locked .uwq-target { cursor:default; }
.uwq-locked .uwq-opt:hover { background:none; }
.uwq-locked .uwq-chip { opacity:0.75; }
/* fill in the blank */
.uwq-blank { display:inline-block; width:120px; padding:3px 8px; margin:0 3px; border:none; border-bottom:2px solid rgba(94,238,248,0.55); background:rgba(255,255,255,0.06); color:inherit; font-size:0.95rem; outline:none; border-radius:4px 4px 0 0; }
.uwq-blank:focus { border-bottom-color:#5eeec8; }
.uwq-blank.bl-correct { border-bottom-color:#5eeec8; background:rgba(94,238,200,0.14); }
.uwq-blank.bl-wrong { border-bottom-color:#ff7676; background:rgba(255,90,90,0.12); }
.uwq-blank-prompt { line-height:2; }
/* image options */
.uwq-img-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(130px,1fr)); gap:10px; }
.uwq-img-opt { position:relative; display:block; border:2px solid rgba(255,255,255,0.14); border-radius:10px; overflow:hidden; cursor:pointer; background:rgba(255,255,255,0.04); }
.uwq-img-opt input { position:absolute; top:8px; left:8px; width:18px; height:18px; accent-color:#5eeef8; z-index:2; }
.uwq-img-opt img { display:block; width:100%; height:120px; object-fit:cover; }
.uwq-img-opt.is-picked { border-color:#5eeec8; }
.uwq-img-cap { font-size:0.78rem; padding:6px 8px; opacity:0.85; }
.uwq-img-opt.opt-correct { border-color:#5eeec8; box-shadow:0 0 0 2px rgba(94,238,200,0.4) inset; }
.uwq-img-opt.opt-chosen-wrong { border-color:#ff7676; box-shadow:0 0 0 2px rgba(255,90,90,0.4) inset; }
.uwq-cell-img { display:block; max-width:100%; max-height:90px; object-fit:contain; border-radius:6px; }
/* matching */
.uwq-match-help { font-size:0.78rem; opacity:0.6; margin:0 0 10px; }
.uwq-match-pool { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:14px; min-height:8px; }
.uwq-chip { display:inline-flex; align-items:center; gap:6px; padding:6px 11px; border-radius:9px; border:1px solid rgba(94,238,248,0.4); background:rgba(94,238,248,0.08); cursor:pointer; font-size:0.9rem; user-select:none; }
.uwq-chip.is-selected { background:rgba(94,238,248,0.28); border-color:#5eeef8; }
.uwq-chip img { max-height:40px; border-radius:4px; }
.uwq-match-targets { display:flex; flex-direction:column; gap:8px; }
.uwq-target { display:flex; align-items:center; gap:10px; padding:8px 10px; border:1px dashed rgba(255,255,255,0.22); border-radius:10px; }
.uwq-target.is-droppable { border-color:rgba(94,238,248,0.7); background:rgba(94,238,248,0.05); cursor:pointer; }
.uwq-target-desc { flex:1; min-width:0; font-size:0.9rem; }
.uwq-target-slot { flex-shrink:0; min-width:90px; min-height:34px; display:flex; align-items:center; justify-content:center; border-radius:8px; background:rgba(255,255,255,0.05); padding:2px; }
.uwq-target.bl-correct { border-style:solid; border-color:#5eeec8; }
.uwq-target.bl-wrong { border-style:solid; border-color:#ff7676; }
/* ordering */
.uwq-order { display:flex; flex-direction:column; gap:7px; }
.uwq-order-row { display:flex; align-items:center; gap:10px; padding:8px 10px; border:1px solid rgba(255,255,255,0.14); border-radius:9px; background:rgba(255,255,255,0.04); }
.uwq-order-pos { min-width:22px; height:22px; border-radius:50%; display:inline-flex; align-items:center; justify-content:center; background:rgba(94,238,248,0.18); color:#5eeef8; font-size:0.74rem; font-weight:700; flex-shrink:0; }
.uwq-order-body { flex:1; min-width:0; font-size:0.9rem; }
.uwq-order-moves { display:flex; flex-direction:column; gap:2px; }
.uwq-move { width:30px; height:22px; border:1px solid rgba(255,255,255,0.18); background:rgba(255,255,255,0.06); color:inherit; border-radius:6px; cursor:pointer; line-height:1; font-size:0.7rem; }
.uwq-move:disabled { opacity:0.3; cursor:default; }
.uwq-order-row.bl-correct { border-color:#5eeec8; }
.uwq-order-row.bl-wrong { border-color:#ff7676; }
/* coding */
.uwq-code-meta { font-size:0.82rem; opacity:0.75; margin:0 0 8px; }
.uwq-code-lang { display:inline-block; font-weight:800; font-size:0.72rem; letter-spacing:0.04em; text-transform:uppercase; padding:2px 8px; border-radius:5px; background:rgba(94,238,248,0.16); color:#5eeef8; margin-right:6px; }
.uwq-code { width:100%; min-height:180px; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:0.88rem; line-height:1.5; padding:10px 12px; border-radius:10px; border:1px solid rgba(255,255,255,0.18); background:rgba(10,12,18,0.7); color:#e6e6e6; outline:none; resize:vertical; tab-size:4; }
.uwq-code:focus { border-color:rgba(94,238,248,0.5); }
.uwq .CodeMirror { border:1px solid rgba(255,255,255,0.18); border-radius:10px; height:auto; font-size:0.88rem; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
.uwq .CodeMirror-scroll { min-height:180px; }
.uwq-code-results { margin-top:12px; display:flex; flex-direction:column; gap:8px; }
.uwq-code-banner { padding:9px 12px; border-radius:8px; font-size:0.85rem; background:rgba(255,255,255,0.05); }
.uwq-code-banner.is-err { background:rgba(255,90,90,0.12); color:#ff9b9b; }
.uwq-code-label { font-size:0.7rem; text-transform:uppercase; letter-spacing:0.05em; opacity:0.55; margin:6px 0 3px; }
.uwq-code-pre { margin:0; padding:9px 11px; border-radius:8px; background:rgba(10,12,18,0.7); border:1px solid rgba(255,255,255,0.1); font-family:ui-monospace,Menlo,Consolas,monospace; font-size:0.82rem; line-height:1.45; white-space:pre-wrap; word-break:break-word; max-height:220px; overflow:auto; }
.uwq-code-pre.is-err { color:#ff9b9b; border-color:rgba(255,90,90,0.3); }
.uwq-code-pre.is-exp { color:#aef7e8; border-color:rgba(94,238,200,0.3); }
.uwq-code-test { padding:10px 12px; border-radius:10px; border:1px solid rgba(255,255,255,0.12); }
.uwq-code-test.is-pass { border-color:rgba(94,238,200,0.45); background:rgba(94,238,200,0.06); }
.uwq-code-test.is-fail { border-color:rgba(255,90,90,0.4); background:rgba(255,90,90,0.05); }
.uwq-code-test-head { font-size:0.85rem; font-weight:700; }
/* reflection */
.uwq-reflect { width:100%; min-height:110px; padding:11px 13px; border-radius:10px; border:1px solid rgba(255,255,255,0.18); background:rgba(255,255,255,0.06); color:inherit; font:inherit; font-size:0.93rem; line-height:1.55; outline:none; resize:vertical; box-sizing:border-box; }
.uwq-reflect:focus { border-color:rgba(94,238,248,0.5); }
.uwq-reflect-note { font-size:0.78rem; opacity:0.55; margin:6px 0 0; }
.uwq-reflect-note i { color:#5eeec8; margin-right:5px; }
/* flashcards */
.uwq-fc { max-width:440px; }
.uwq-fc-bar { display:flex; align-items:center; gap:10px; margin-bottom:10px; font-size:0.82rem; opacity:0.85; }
.uwq-fc-restart { margin-left:auto; padding:4px 12px; border-radius:99px; border:1px solid rgba(255,255,255,0.2); background:rgba(255,255,255,0.06); color:inherit; font-size:0.76rem; font-weight:700; cursor:pointer; }
.uwq-fc-restart:hover { border-color:rgba(94,238,248,0.5); }
.uwq-fc-stage { position:relative; perspective:1000px; height:200px; }
/* The rest of the stack: each under-card is a real, opaque card — solid
   background occluding the one beneath, crisp edge, a touch of rotation like
   a hand-stacked deck. Depth fades by darkening, not transparency. */
.uwq-fc-under { position:absolute; inset:0; border-radius:14px; border:1px solid rgba(255,255,255,0.22); background:#161c25; box-shadow:0 3px 9px rgba(0,0,0,0.4); transition:transform 0.3s ease, opacity 0.3s ease; }
.uwq-fc-under.u1 { transform:translateY(9px) rotate(-1.6deg) scale(0.99); background:#141a22; }
.uwq-fc-under.u2 { transform:translateY(17px) rotate(-3.2deg) scale(0.98); background:#10151c; border-color:rgba(255,255,255,0.18); opacity:0.9; }
@keyframes uwqFcIn { from { opacity:0; transform:translateY(10px) scale(0.98); } to { opacity:1; transform:none; } }
.uwq-fc-card { position:absolute; inset:0; cursor:pointer; transform-style:preserve-3d; transition:transform 0.45s cubic-bezier(0.4,0.2,0.2,1); animation:uwqFcIn 0.25s ease; }
.uwq-fc-card.is-flipped { transform:rotateY(180deg); }
.uwq-fc-face { position:absolute; inset:0; backface-visibility:hidden; -webkit-backface-visibility:hidden; display:flex; align-items:center; justify-content:center; text-align:center; padding:18px 20px 26px; border-radius:14px; font-size:1rem; line-height:1.5; overflow:auto; color:#e8edf2; box-shadow:0 8px 22px rgba(0,0,0,0.35); }
.uwq-fc-front { background:linear-gradient(rgba(94,238,248,0.1), rgba(94,238,248,0.1)), #151b23; border:1px solid rgba(94,238,248,0.35); }
.uwq-fc-back { background:linear-gradient(rgba(94,238,200,0.12), rgba(94,238,200,0.12)), #151b23; border:1px solid rgba(94,238,200,0.4); transform:rotateY(180deg); }
.uwq-fc-hint { position:absolute; bottom:8px; left:0; right:0; text-align:center; font-size:0.66rem; letter-spacing:0.07em; text-transform:uppercase; opacity:0.45; }
.uwq-fc-media { display:flex; flex-direction:column; align-items:center; gap:8px; max-width:100%; }
.uwq-fc-img { max-width:100%; max-height:120px; object-fit:contain; border-radius:8px; }
.uwq-fc-cap { font-size:0.9rem; opacity:0.88; }
.uwq-fc-judge { display:flex; gap:10px; margin-top:26px; }
.uwq-fc-btn { flex:1; padding:10px 0; border-radius:10px; font-weight:800; font-size:0.88rem; cursor:pointer; border:1px solid; background:transparent; color:inherit; transition:opacity 0.15s, transform 0.15s; }
.uwq-fc-btn:disabled { opacity:0.35; cursor:default; }
.uwq-fc-btn:not(:disabled):hover { transform:translateY(-1px); }
.uwq-fc-no { border-color:rgba(255,150,90,0.5); color:#ffb27a; }
.uwq-fc-yes { border-color:rgba(94,238,200,0.55); color:#5eeec8; }
.uwq-fc-done { display:flex; flex-direction:column; align-items:center; justify-content:center; gap:8px; height:200px; border-radius:14px; border:1px dashed rgba(94,238,200,0.4); background:rgba(94,238,200,0.05); text-align:center; }
.uwq-fc-done i { font-size:1.7rem; color:#5eeec8; }
.uwq-fc-done p { margin:0; font-weight:700; }
`;
        const style = document.createElement('style');
        style.id = 'uwq-styles';
        style.textContent = css;
        document.head.appendChild(style);
    }

    // ── link auto-embedding ─────────────────────────────────────────────────
    // YouTube / Vimeo URLs → player iframe src; anything else → null.
    function videoEmbedUrl(url) {
        let m = url.match(/(?:youtube\.com\/(?:watch\?[^\s]*?v=|shorts\/|embed\/|live\/)|youtu\.be\/)([A-Za-z0-9_-]{6,})/);
        if (m) return 'https://www.youtube-nocookie.com/embed/' + m[1];
        m = url.match(/vimeo\.com\/(\d+)/);
        if (m) return 'https://player.vimeo.com/video/' + m[1];
        return null;
    }

    // Escape text, turn URLs into anchors, keep newlines, and collect media
    // embeds (video players / images) to render below the text.
    function linkifyParts(text) {
        const src = String(text == null ? '' : text);
        const embeds = [];
        const re = /https?:\/\/[^\s<>"']+/g;
        let html = '';
        let last = 0;
        let m;
        while ((m = re.exec(src)) !== null) {
            const url = m[0].replace(/[.,;:!?)\]]+$/, '');
            html += esc(src.slice(last, m.index));
            html += '<a class="uwq-link" href="' + esc(url) + '" target="_blank" rel="noopener">' + esc(url) + '</a>';
            last = m.index + url.length;
            const v = videoEmbedUrl(url);
            if (v) {
                embeds.push('<div class="uwq-embed-frame"><iframe src="' + esc(v) + '" loading="lazy" allowfullscreen allow="autoplay; encrypted-media; picture-in-picture"></iframe></div>');
            } else if (/\.(png|jpe?g|gif|webp|svg)([?#]|$)/i.test(url)) {
                embeds.push('<img class="uwq-embed-img" src="' + esc(url) + '" alt="" loading="lazy">');
            }
        }
        html += esc(src.slice(last));
        return { html: html.replace(/\n/g, '<br>'), embeds: embeds };
    }

    function embedsHtml(embeds) {
        return embeds.length ? '<div class="uwq-embeds">' + embeds.join('') + '</div>' : '';
    }

    function cellHtml(cell) {
        if (cell && cell.kind === 'image' && cell.image_url) {
            return '<img class="uwq-cell-img" src="' + esc(cell.image_url) + '" alt="' + esc(cell.text || '') + '">'
                + (cell.text ? '<span class="uwq-img-cap">' + esc(cell.text) + '</span>' : '');
        }
        return esc((cell && cell.text) || '');
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
        // Only on first load — a Retake starts from a blank form.
        renderQuiz(el, data.quiz, data.quiz.draft);
    }

    function renderQuiz(el, quiz, draft) {
        el._quiz = quiz;
        el._locked = false;   // a fresh form is editable (Retake unlocks this way)
        el._mstate = {};  // matching: qid -> {leftId: rightId}
        el._ostate = {};  // ordering: qid -> [itemId,...]
        el._sel = {};     // matching: qid -> currently picked leftId
        el._fc = {};      // flashcards: qid -> {queue:[cardId,...], flipped:bool}
        let html = '<div class="uwq"><div class="uwq-head"><i class="fas fa-clipboard-check"></i><h3>' + esc(quiz.title) + '</h3></div>';
        if (quiz.description) {
            const d = linkifyParts(quiz.description);
            html += '<p class="uwq-desc">' + d.html + '</p>' + embedsHtml(d.embeds);
        }
        html += '<form class="uwq-form">';
        // Text blocks are content, not questions — they don't get a number.
        let qnum = 0;
        (quiz.questions || []).forEach(q => {
            html += renderQuestion(q, q.question_type === 'text' ? 0 : ++qnum);
        });
        // A quiz with nothing gradable (reflections/flashcards/text only)
        // reads as a save form, not a test.
        const hasGraded = (quiz.questions || []).some(q =>
            q.question_type !== 'reflection' && q.question_type !== 'flashcards' &&
            q.question_type !== 'text');
        html += '<div class="uwq-actions"><button type="submit" class="uwq-submit">'
              + (hasGraded ? 'Submit' : 'Save') + '</button><span class="uwq-score"></span></div>';
        html += '</form></div>';
        el.innerHTML = html;

        // Seed interactive widget state (from draft when present) then paint.
        (quiz.questions || []).forEach(q => {
            if (q.question_type === 'ordering') {
                let order = (q.items || []).map(it => it.id);
                if (draft && Array.isArray(draft[q.id]) &&
                    draft[q.id].length === order.length &&
                    draft[q.id].every(id => order.indexOf(id) >= 0)) {
                    order = draft[q.id].slice();
                }
                el._ostate[q.id] = order;
                renderOrdering(el, q);
            } else if (q.question_type === 'matching') {
                const map = {};
                if (draft && draft[q.id] && typeof draft[q.id] === 'object') {
                    Object.keys(draft[q.id]).forEach(k => { map[k] = draft[q.id][k]; });
                }
                el._mstate[q.id] = map;
                renderMatching(el, q);
            } else if (q.question_type === 'flashcards') {
                renderFlashcards(el, q);
            }
        });

        // Attempt limits: surface usage, and gate the form when exhausted or
        // cooling down (the server enforces this regardless).
        const actionsRow = el.querySelector('.uwq-actions');
        const submitBtn = el.querySelector('.uwq-submit');
        if (quiz.max_attempts) {
            const hint = document.createElement('p');
            hint.className = 'uwq-attempts';
            hint.textContent = 'Attempts used: ' + (quiz.attempts_used || 0) + ' / ' + quiz.max_attempts;
            actionsRow.appendChild(hint);
        }
        if (quiz.attempts_left === 0) {
            submitBtn.disabled = true;
            const g = document.createElement('p');
            g.className = 'uwq-gate';
            g.textContent = 'You\'ve used all ' + quiz.max_attempts + ' attempts for this quiz.';
            actionsRow.appendChild(g);
        } else if (quiz.cooldown_seconds > 0) {
            submitBtn.disabled = true;
            const g = document.createElement('p');
            g.className = 'uwq-gate';
            g.textContent = 'Next attempt available in about ' + Math.max(1, Math.ceil(quiz.cooldown_seconds / 60)) + ' min.';
            actionsRow.appendChild(g);
            setTimeout(() => { submitBtn.disabled = false; g.remove(); }, quiz.cooldown_seconds * 1000);
        }

        const form = el.querySelector('.uwq-form');
        form.addEventListener('submit', ev => { ev.preventDefault(); submit(el, quiz); });
        if (draft) applyDraft(el, quiz, draft);
        // Reflections: when the draft doesn't already carry text, prefill from
        // the reader's most recent submitted response (server-provided).
        if (quiz.reflections) {
            (quiz.questions || []).forEach(q => {
                if (q.question_type !== 'reflection') return;
                const ta = el.querySelector('.uwq-q[data-qid="' + q.id + '"] .uwq-reflect');
                const saved = quiz.reflections[String(q.id)];
                if (ta && !ta.value && typeof saved === 'string') ta.value = saved;
            });
        }
        form.addEventListener('input', () => scheduleDraftSave(el, quiz));
        form.addEventListener('change', () => {
            (quiz.questions || []).forEach(q => { if (q.question_type === 'image_choice') syncImgPicked(el, q); });
            scheduleDraftSave(el, quiz);
        });
        // Upgrade coding textareas to CodeMirror once it has loaded (the plain
        // textarea works as a fallback meanwhile). Done after applyDraft so the
        // editor inherits any restored draft text.
        if ((quiz.questions || []).some(q => q.question_type === 'coding')) {
            const langs = (quiz.questions || []).filter(q => q.question_type === 'coding').map(q => q.language);
            ensureCodeMirror(langs).then(() => initCodeEditors(el, quiz)).catch(() => {});
        }
    }

    // ── coding: CodeMirror lazy loader + editor init ─────────────────────────
    const CODE_LANG_LABELS = { python: 'Python', javascript: 'JavaScript', java: 'Java', c: 'C', cpp: 'C++' };
    const CODE_CM_MODE = { python: 'python', javascript: 'javascript', java: 'text/x-java', c: 'text/x-csrc', cpp: 'text/x-c++src' };
    const CODE_CM_MODE_FILE = { python: 'python/python', javascript: 'javascript/javascript', java: 'clike/clike', c: 'clike/clike', cpp: 'clike/clike' };
    const _CM_BASE = 'https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16';
    let _cmLoad = null;

    function _loadCss(href) {
        if (document.querySelector('link[href="' + href + '"]')) return;
        const l = document.createElement('link');
        l.rel = 'stylesheet'; l.href = href;
        document.head.appendChild(l);
    }
    function _loadScript(src) {
        return new Promise((resolve, reject) => {
            if (document.querySelector('script[src="' + src + '"]')) { resolve(); return; }
            const s = document.createElement('script');
            s.src = src; s.onload = resolve; s.onerror = reject;
            document.head.appendChild(s);
        });
    }
    function ensureCodeMirror(langs) {
        if (_cmLoad) return _cmLoad;
        _cmLoad = (async () => {
            _loadCss(_CM_BASE + '/codemirror.min.css');
            _loadCss(_CM_BASE + '/theme/material-darker.min.css');
            await _loadScript(_CM_BASE + '/codemirror.min.js');
            const modeFiles = new Set((langs || []).map(l => CODE_CM_MODE_FILE[l]).filter(Boolean));
            for (const mf of modeFiles) {
                try { await _loadScript(_CM_BASE + '/mode/' + mf + '.min.js'); } catch (e) { /* fallback to plain */ }
            }
        })();
        return _cmLoad;
    }
    function initCodeEditors(el, quiz) {
        if (!window.CodeMirror) return;
        (quiz.questions || []).forEach(q => {
            if (q.question_type !== 'coding') return;
            const ta = el.querySelector('.uwq-q[data-qid="' + q.id + '"] .uwq-code');
            if (!ta || ta._cm) return;
            const cm = window.CodeMirror.fromTextArea(ta, {
                mode: CODE_CM_MODE[q.language] || 'text/plain',
                theme: 'material-darker',
                lineNumbers: true,
                indentUnit: 4,
                tabSize: 4,
                matchBrackets: true,
                autoCloseBrackets: true,
                viewportMargin: Infinity,
            });
            cm.setSize('100%', 'auto');
            cm.on('change', () => scheduleDraftSave(el, el._quiz));
            ta._cm = cm;
        });
    }

    function renderQuestion(q, num) {
        const t = q.question_type;
        let h = '<div class="uwq-q" data-qid="' + q.id + '" data-qtype="' + t + '">';
        const rich = linkifyParts(q.prompt);
        if (t === 'text') {
            // Content block — no number, no inputs, nothing to grade.
            return h + '<div class="uwq-text-body">' + rich.html + '</div>' + embedsHtml(rich.embeds) + '</div>';
        }
        if (t === 'fill_blank') {
            h += '<p class="uwq-prompt uwq-blank-prompt"><span class="uwq-num">' + num + '</span><span>' + blankPromptHtml(q) + '</span></p>';
        } else {
            h += '<p class="uwq-prompt"><span class="uwq-num">' + num + '</span><span>' + rich.html + '</span></p>';
        }
        h += embedsHtml(rich.embeds);
        if (t === 'short_text') {
            h += '<input type="text" class="uwq-text" name="q' + q.id + '" autocomplete="off">';
        } else if (t === 'single_choice' || t === 'multi_choice' || t === 'true_false') {
            const inputType = (t === 'multi_choice') ? 'checkbox' : 'radio';
            (q.options || []).forEach(o => {
                h += '<label class="uwq-opt"><input type="' + inputType + '" name="q' + q.id + '" value="' + o.id + '"> <span>' + esc(o.text) + '</span></label>';
            });
        } else if (t === 'image_choice') {
            const inputType = q.multiple ? 'checkbox' : 'radio';
            h += '<div class="uwq-img-grid">';
            (q.options || []).forEach(o => {
                h += '<label class="uwq-img-opt" data-oid="' + o.id + '">'
                    + '<input type="' + inputType + '" name="q' + q.id + '" value="' + o.id + '">'
                    + '<img src="' + esc(o.image_url) + '" alt="' + esc(o.caption || '') + '">'
                    + (o.caption ? '<div class="uwq-img-cap">' + esc(o.caption) + '</div>' : '')
                    + '</label>';
            });
            h += '</div>';
        } else if (t === 'matching') {
            h += '<p class="uwq-match-help">Tap an item, then tap the description it matches. Tap a placed item to send it back.</p>';
            h += '<div class="uwq-match" data-qid="' + q.id + '"></div>';
        } else if (t === 'ordering') {
            h += '<p class="uwq-match-help">Put these in the correct order using the arrows.</p>';
            h += '<div class="uwq-order" data-qid="' + q.id + '"></div>';
        } else if (t === 'coding') {
            const langLabel = CODE_LANG_LABELS[q.language] || q.language;
            const modeNote = (q.mode === 'compile')
                ? 'Passes if your code compiles cleanly.'
                : 'Runs against ' + (q.test_count || 0) + ' hidden test case' + ((q.test_count === 1) ? '' : 's') + ' — all must pass.';
            h += '<p class="uwq-code-meta"><span class="uwq-code-lang">' + esc(langLabel) + '</span> ' + esc(modeNote) + '</p>';
            h += '<textarea class="uwq-code" data-lang="' + esc(q.language) + '" spellcheck="false">' + esc(q.starter_code || '') + '</textarea>';
            h += '<div class="uwq-code-results" style="display:none;"></div>';
        } else if (t === 'reflection') {
            h += '<textarea class="uwq-reflect" name="q' + q.id + '" placeholder="Write your thoughts…"></textarea>';
            h += '<p class="uwq-reflect-note"><i class="fas fa-comment-dots"></i>Reflection — there\'s no right or wrong answer. Your response is saved with your submission and will be here when you come back.</p>';
        } else if (t === 'flashcards') {
            h += '<div class="uwq-fc" data-qid="' + q.id + '"></div>';
        }
        h += '<div class="uwq-fb" style="display:none;"></div></div>';
        return h;
    }

    // fill_blank: render prompt text with <input> in place of each ___ marker.
    function blankPromptHtml(q) {
        const parts = String(q.prompt || '').split(/_{3,}/);
        let h = '';
        parts.forEach((seg, i) => {
            h += linkifyParts(seg).html;
            if (i < parts.length - 1) {
                h += '<input type="text" class="uwq-blank" data-bi="' + i + '" autocomplete="off">';
            }
        });
        return h;
    }

    // ── flashcards ──────────────────────────────────────────────────────────
    // A card side is a cell: text, or an image with an optional caption.
    // (Legacy payloads may still carry plain strings.)
    function fcFaceHtml(side) {
        if (typeof side === 'string') return '<span>' + esc(side) + '</span>';
        if (side && side.kind === 'image' && side.image_url) {
            return '<span class="uwq-fc-media">'
                + '<img class="uwq-fc-img" src="' + esc(side.image_url) + '" alt="' + esc(side.text || '') + '">'
                + (side.text ? '<span class="uwq-fc-cap">' + esc(side.text) + '</span>' : '')
                + '</span>';
        }
        return '<span>' + esc((side && side.text) || '') + '</span>';
    }

    function shuffledIds(cards) {
        const ids = (cards || []).map(c => c.id);
        for (let i = ids.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            const t = ids[i]; ids[i] = ids[j]; ids[j] = t;
        }
        return ids;
    }

    function renderFlashcards(el, q) {
        const wrap = el.querySelector('.uwq-fc[data-qid="' + q.id + '"]');
        if (!wrap) return;
        const cards = q.cards || [];
        const byId = {};
        cards.forEach(c => { byId[c.id] = c; });
        let st = el._fc[q.id];
        if (!st) st = el._fc[q.id] = { queue: shuffledIds(cards), flipped: false };
        const remaining = st.queue.length;

        let h = '<div class="uwq-fc-bar"><span>' + (cards.length - remaining) + ' / ' + cards.length + ' cleared</span>'
              + '<button type="button" class="uwq-fc-restart"><i class="fas fa-undo"></i> Restart</button></div>';

        if (!remaining) {
            h += '<div class="uwq-fc-done"><i class="fas fa-check-circle"></i>'
               + '<p>All cards cleared!</p>'
               + '<span style="font-size:0.8rem;opacity:0.6;">Restart the stack to run through them again.</span></div>';
        } else {
            const cur = byId[st.queue[0]] || { front: '', back: '' };
            h += '<div class="uwq-fc-stage">'
               + (remaining > 2 ? '<div class="uwq-fc-under u2"></div>' : '')
               + (remaining > 1 ? '<div class="uwq-fc-under u1"></div>' : '')
               + '<div class="uwq-fc-card' + (st.flipped ? ' is-flipped' : '') + '">'
               + '<div class="uwq-fc-face uwq-fc-front">' + fcFaceHtml(cur.front) + '<span class="uwq-fc-hint">Tap to flip</span></div>'
               + '<div class="uwq-fc-face uwq-fc-back">' + fcFaceHtml(cur.back) + '<span class="uwq-fc-hint">Did you know it?</span></div>'
               + '</div></div>'
               + '<div class="uwq-fc-judge">'
               + '<button type="button" class="uwq-fc-btn uwq-fc-no"' + (st.flipped ? '' : ' disabled') + '><i class="fas fa-times"></i> Didn\'t get it</button>'
               + '<button type="button" class="uwq-fc-btn uwq-fc-yes"' + (st.flipped ? '' : ' disabled') + '><i class="fas fa-check"></i> Got it</button>'
               + '</div>';
        }
        wrap.innerHTML = h;

        const restart = wrap.querySelector('.uwq-fc-restart');
        if (restart) restart.addEventListener('click', () => {
            el._fc[q.id] = { queue: shuffledIds(cards), flipped: false };
            renderFlashcards(el, q);
        });
        const cardEl = wrap.querySelector('.uwq-fc-card');
        if (cardEl) cardEl.addEventListener('click', () => {
            st.flipped = !st.flipped;
            cardEl.classList.toggle('is-flipped', st.flipped);
            wrap.querySelectorAll('.uwq-fc-btn').forEach(b => { b.disabled = !st.flipped; });
        });
        const noBtn = wrap.querySelector('.uwq-fc-no');
        if (noBtn) noBtn.addEventListener('click', () => {
            // Back into the stack at a random depth (never the very top, so the
            // reader sees at least one other card first when there is one).
            const id = st.queue.shift();
            const pos = st.queue.length ? 1 + Math.floor(Math.random() * st.queue.length) : 0;
            st.queue.splice(pos, 0, id);
            st.flipped = false;
            renderFlashcards(el, q);
        });
        const yesBtn = wrap.querySelector('.uwq-fc-yes');
        if (yesBtn) yesBtn.addEventListener('click', () => {
            st.queue.shift();          // cleared — out of the stack
            st.flipped = false;
            renderFlashcards(el, q);
        });
    }

    // ── matching ────────────────────────────────────────────────────────────
    function renderMatching(el, q) {
        const wrap = el.querySelector('.uwq-match[data-qid="' + q.id + '"]');
        if (!wrap) return;
        const map = el._mstate[q.id] || (el._mstate[q.id] = {});
        const placed = {};                       // rightId -> leftId
        Object.keys(map).forEach(lid => { placed[map[lid]] = lid; });
        const leftById = {};
        (q.lefts || []).forEach(l => { leftById[l.id] = l; });
        const sel = el._sel[q.id];

        let h = '<div class="uwq-match-pool">';
        (q.lefts || []).forEach(l => {
            if (map[l.id] != null) return;        // placed → not in pool
            h += '<span class="uwq-chip' + (sel === l.id ? ' is-selected' : '') + '" data-lid="' + l.id + '">' + cellHtml(l) + '</span>';
        });
        h += '</div><div class="uwq-match-targets">';
        (q.rights || []).forEach(r => {
            const lid = placed[r.id];
            h += '<div class="uwq-target' + (sel != null ? ' is-droppable' : '') + '" data-rid="' + r.id + '">'
                + '<div class="uwq-target-desc">' + cellHtml(r) + '</div>'
                + '<div class="uwq-target-slot">'
                + (lid != null ? '<span class="uwq-chip" data-lid="' + lid + '" data-placed="1">' + cellHtml(leftById[lid]) + '</span>' : '')
                + '</div></div>';
        });
        h += '</div>';
        wrap.innerHTML = h;

        wrap.querySelectorAll('.uwq-chip[data-placed="1"]').forEach(chip => {
            chip.addEventListener('click', ev => {
                ev.stopPropagation();
                if (el._locked) return;
                const lid = parseInt(chip.dataset.lid);
                delete el._mstate[q.id][lid];      // back to pool
                el._sel[q.id] = null;
                renderMatching(el, q); scheduleDraftSave(el, el._quiz);
            });
        });
        wrap.querySelectorAll('.uwq-match-pool .uwq-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                if (el._locked) return;
                const lid = parseInt(chip.dataset.lid);
                el._sel[q.id] = (el._sel[q.id] === lid) ? null : lid;
                renderMatching(el, q);
            });
        });
        wrap.querySelectorAll('.uwq-target').forEach(tg => {
            tg.addEventListener('click', () => {
                if (el._locked) return;
                const picked = el._sel[q.id];
                if (picked == null) return;
                const rid = parseInt(tg.dataset.rid);
                // Clear whoever currently sits on this target, and any prior
                // placement of the picked item.
                Object.keys(el._mstate[q.id]).forEach(k => {
                    if (el._mstate[q.id][k] === rid) delete el._mstate[q.id][k];
                });
                el._mstate[q.id][picked] = rid;
                el._sel[q.id] = null;
                renderMatching(el, q); scheduleDraftSave(el, el._quiz);
            });
        });
    }

    // ── ordering ────────────────────────────────────────────────────────────
    function renderOrdering(el, q) {
        const wrap = el.querySelector('.uwq-order[data-qid="' + q.id + '"]');
        if (!wrap) return;
        const order = el._ostate[q.id] || [];
        const byId = {};
        (q.items || []).forEach(it => { byId[it.id] = it; });
        let h = '';
        order.forEach((id, i) => {
            h += '<div class="uwq-order-row" data-id="' + id + '">'
                + '<span class="uwq-order-pos">' + (i + 1) + '</span>'
                + '<div class="uwq-order-body">' + cellHtml(byId[id]) + '</div>'
                + '<div class="uwq-order-moves">'
                + '<button type="button" class="uwq-move" data-dir="-1" ' + (i === 0 ? 'disabled' : '') + '>▲</button>'
                + '<button type="button" class="uwq-move" data-dir="1" ' + (i === order.length - 1 ? 'disabled' : '') + '>▼</button>'
                + '</div></div>';
        });
        wrap.innerHTML = h;
        wrap.querySelectorAll('.uwq-move').forEach(btn => {
            btn.addEventListener('click', () => {
                if (el._locked) return;
                const row = btn.closest('.uwq-order-row');
                const id = parseInt(row.dataset.id);
                const dir = parseInt(btn.dataset.dir);
                const arr = el._ostate[q.id];
                const idx = arr.indexOf(id);
                const j = idx + dir;
                if (j < 0 || j >= arr.length) return;
                arr[idx] = arr[j]; arr[j] = id;
                renderOrdering(el, q); scheduleDraftSave(el, el._quiz);
            });
        });
    }

    function collect(el, quiz) {
        const answers = {};
        (quiz.questions || []).forEach(q => {
            const name = 'q' + q.id;
            const t = q.question_type;
            if (t === 'short_text') {
                const inp = el.querySelector('input[name="' + name + '"]');
                answers[q.id] = inp ? inp.value : '';
            } else if (t === 'multi_choice' || (t === 'image_choice' && q.multiple)) {
                answers[q.id] = Array.from(el.querySelectorAll('input[name="' + name + '"]:checked')).map(i => parseInt(i.value));
            } else if (t === 'single_choice' || t === 'true_false' || t === 'image_choice') {
                const sel = el.querySelector('input[name="' + name + '"]:checked');
                answers[q.id] = sel ? parseInt(sel.value) : null;
            } else if (t === 'fill_blank') {
                const qEl = el.querySelector('.uwq-q[data-qid="' + q.id + '"]');
                const inputs = Array.from(qEl.querySelectorAll('.uwq-blank'))
                    .sort((a, b) => parseInt(a.dataset.bi) - parseInt(b.dataset.bi));
                answers[q.id] = inputs.map(i => i.value);
            } else if (t === 'matching') {
                answers[q.id] = el._mstate[q.id] || {};
            } else if (t === 'ordering') {
                answers[q.id] = (el._ostate[q.id] || []).slice();
            } else if (t === 'coding') {
                const ta = el.querySelector('.uwq-q[data-qid="' + q.id + '"] .uwq-code');
                answers[q.id] = ta ? (ta._cm ? ta._cm.getValue() : ta.value) : '';
            } else if (t === 'reflection') {
                const ta = el.querySelector('.uwq-q[data-qid="' + q.id + '"] .uwq-reflect');
                answers[q.id] = ta ? ta.value : '';
            }
            // flashcards: a study widget — nothing to submit.
        });
        return answers;
    }

    // Restore previously-saved answers onto a freshly rendered form. Matching
    // and ordering state is seeded in renderQuiz; here we cover the inputs.
    function applyDraft(el, quiz, draft) {
        (quiz.questions || []).forEach(q => {
            if (!(q.id in draft)) return;
            const val = draft[q.id];
            const name = 'q' + q.id;
            const t = q.question_type;
            if (t === 'short_text') {
                const inp = el.querySelector('input[name="' + name + '"]');
                if (inp && val != null) inp.value = val;
            } else if (t === 'multi_choice' || (t === 'image_choice' && q.multiple)) {
                const picked = Array.isArray(val) ? val.map(String) : [];
                el.querySelectorAll('input[name="' + name + '"]').forEach(i => { i.checked = picked.indexOf(String(i.value)) >= 0; });
                if (t === 'image_choice') syncImgPicked(el, q);
            } else if (t === 'single_choice' || t === 'true_false' || t === 'image_choice') {
                el.querySelectorAll('input[name="' + name + '"]').forEach(i => { i.checked = String(i.value) === String(val); });
                if (t === 'image_choice') syncImgPicked(el, q);
            } else if (t === 'fill_blank') {
                const qEl = el.querySelector('.uwq-q[data-qid="' + q.id + '"]');
                const inputs = Array.from(qEl.querySelectorAll('.uwq-blank'))
                    .sort((a, b) => parseInt(a.dataset.bi) - parseInt(b.dataset.bi));
                (Array.isArray(val) ? val : []).forEach((v, i) => { if (inputs[i] && v != null) inputs[i].value = v; });
            } else if (t === 'coding') {
                // Set the textarea now; CodeMirror inherits it when it inits.
                const ta = el.querySelector('.uwq-q[data-qid="' + q.id + '"] .uwq-code');
                if (ta && typeof val === 'string') { if (ta._cm) ta._cm.setValue(val); else ta.value = val; }
            } else if (t === 'reflection') {
                const ta = el.querySelector('.uwq-q[data-qid="' + q.id + '"] .uwq-reflect');
                if (ta && typeof val === 'string') ta.value = val;
            }
            // matching / ordering already seeded from draft in renderQuiz.
        });
        // Reflect image-choice selection styling for any seeded radios.
        (quiz.questions || []).forEach(q => { if (q.question_type === 'image_choice') syncImgPicked(el, q); });
    }

    // After a graded submit the answers are the record of the attempt — freeze
    // every answer control so edits can only happen through Retake (which
    // re-renders a fresh, unlocked form). Flashcards stay usable: they're a
    // study widget, not an answer.
    function lockQuiz(el, quiz) {
        el._locked = true;
        const box = el.querySelector('.uwq');
        if (box) box.classList.add('uwq-locked');
        el.querySelectorAll('.uwq-form input, .uwq-form textarea, .uwq-form select').forEach(inp => {
            inp.disabled = true;
        });
        el.querySelectorAll('.uwq-move').forEach(b => { b.disabled = true; });
        (quiz.questions || []).forEach(q => {
            if (q.question_type !== 'coding') return;
            const ta = el.querySelector('.uwq-q[data-qid="' + q.id + '"] .uwq-code');
            if (ta && ta._cm) ta._cm.setOption('readOnly', true);
        });
    }

    function syncImgPicked(el, q) {
        el.querySelectorAll('.uwq-q[data-qid="' + q.id + '"] .uwq-img-opt').forEach(lab => {
            const inp = lab.querySelector('input');
            lab.classList.toggle('is-picked', !!(inp && inp.checked));
        });
    }

    function scheduleDraftSave(el, quiz) {
        // A submitted (locked) form must not autosave — the attempt is the
        // record now, and a stray draft would prefill stale answers next visit.
        if (!quiz || el._locked) return;
        clearTimeout(el._uwqDraftTimer);
        el._uwqDraftTimer = setTimeout(() => saveDraft(el, quiz), 700);
    }

    function saveDraft(el, quiz) {
        try {
            fetch('/api/quizzes/' + quiz.id + '/draft', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ answers: collect(el, quiz), guide_node_id: window.UW_GUIDE_NODE_ID || null })
            });
        } catch (e) { /* ignore */ }
    }

    async function submit(el, quiz) {
        clearTimeout(el._uwqDraftTimer);
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
        if (!data || !data.success) {
            btn.disabled = false; btn.textContent = 'Submit';
            // Attempt limit / cooldown rejection — surface the server's message.
            if (data && data.message) {
                const actions = el.querySelector('.uwq-actions');
                let g = actions.querySelector('.uwq-gate');
                if (!g) { g = document.createElement('p'); g.className = 'uwq-gate'; actions.appendChild(g); }
                g.textContent = data.message;
                if (data.error === 'attempt_limit') btn.disabled = true;
            }
            return;
        }
        showResults(el, quiz, data);
    }

    function showResults(el, quiz, data) {
        const byId = {};
        (data.results || []).forEach(r => { byId[r.question_id] = r; });
        (quiz.questions || []).forEach(q => {
            const qEl = el.querySelector('.uwq-q[data-qid="' + q.id + '"]');
            const r = byId[q.id];
            if (!qEl || !r) return;
            const t = q.question_type;
            if (r.ungraded) {
                // No right/wrong to paint. Reflections confirm the save.
                qEl.classList.remove('is-correct', 'is-wrong');
                const ufb = qEl.querySelector('.uwq-fb');
                if (t === 'reflection' && ufb) {
                    ufb.style.display = 'block';
                    ufb.innerHTML = r.reflection_saved
                        ? '<span class="uwq-ok">✓ Response saved</span>'
                        : '<span style="opacity:0.6;">No response written — you can add one and resubmit any time.</span>';
                }
                return;
            }
            qEl.classList.remove('is-correct', 'is-wrong');
            qEl.classList.add(r.correct ? 'is-correct' : 'is-wrong');

            if (t === 'single_choice' || t === 'multi_choice' || t === 'true_false') {
                paintChoice(qEl, r, '.uwq-opt', 'input');
            } else if (t === 'image_choice') {
                paintChoice(qEl, r, '.uwq-img-opt', 'input');
            } else if (t === 'fill_blank') {
                const inputs = Array.from(qEl.querySelectorAll('.uwq-blank'))
                    .sort((a, b) => parseInt(a.dataset.bi) - parseInt(b.dataset.bi));
                (r.blank_results || []).forEach((ok, i) => {
                    if (!inputs[i]) return;
                    inputs[i].classList.remove('bl-correct', 'bl-wrong');
                    inputs[i].classList.add(ok ? 'bl-correct' : 'bl-wrong');
                });
            } else if (t === 'matching') {
                // Reveal correct mapping only when the server included it.
                if (r.correct_pairs) {
                    qEl.querySelectorAll('.uwq-target').forEach(tg => {
                        const rid = parseInt(tg.dataset.rid);
                        const placed = tg.querySelector('.uwq-target-slot .uwq-chip');
                        const lid = placed ? parseInt(placed.dataset.lid) : null;
                        const ok = lid != null && r.correct_pairs[String(lid)] === rid;
                        tg.classList.add(ok ? 'bl-correct' : 'bl-wrong');
                    });
                }
            } else if (t === 'ordering') {
                if (r.answer_order) {
                    const order = el._ostate[q.id] || [];
                    qEl.querySelectorAll('.uwq-order-row').forEach((row, i) => {
                        row.classList.add(order[i] === r.answer_order[i] ? 'bl-correct' : 'bl-wrong');
                    });
                }
            } else if (t === 'coding') {
                renderCodeResults(qEl, r);
            }

            const fb = qEl.querySelector('.uwq-fb');
            if (fb) {
                fb.style.display = 'block';
                let txt = r.correct ? '<span class="uwq-ok">Correct</span>'
                        : (r.earned > 0 ? '<span style="color:#ffd28a;font-weight:700;">Partially correct · ' + r.earned + ' / ' + q.points + ' pts</span>'
                                        : '<span class="uwq-no">Incorrect</span>');
                if (t === 'fill_blank' && Array.isArray(r.blank_results)) {
                    const got = r.blank_results.filter(Boolean).length;
                    txt += ' · ' + got + ' / ' + r.blank_results.length + ' blanks';
                }
                if (t === 'coding' && Array.isArray(r.tests)) {
                    const got = r.tests.filter(x => x.passed).length;
                    txt += ' · ' + got + ' / ' + r.tests.length + ' tests passed';
                }
                if (t === 'short_text' && !r.correct && r.accepted && r.accepted.length) {
                    txt += ' · Accepted: ' + r.accepted.map(esc).join(', ');
                }
                fb.innerHTML = txt;
                // Explanation — present when passed, or on correctly answered
                // questions (the server withholds it otherwise).
                if (r.explanation) {
                    const ex = linkifyParts(r.explanation);
                    fb.innerHTML += '<div class="uwq-expl">' + ex.html + '</div>' + embedsHtml(ex.embeds);
                }
            }
        });

        const scoreEl = el.querySelector('.uwq-score');
        const actionsBox = el.querySelector('.uwq-actions');
        if (!data.max_score) {
            // Nothing gradable — no score or pass/fail theater. The button
            // stays a live Save so responses can be revised and resaved.
            scoreEl.textContent = 'Saved ✓';
            const p0 = actionsBox.querySelector('.uwq-status'); if (p0) p0.remove();
            const h0 = actionsBox.querySelector('.uwq-hint'); if (h0) h0.remove();
            const sbtn = el.querySelector('.uwq-submit');
            sbtn.disabled = false;
            sbtn.textContent = 'Save';
            if (data.progress) {
                document.dispatchEvent(new CustomEvent('uwq-progress', { detail: data.progress }));
            }
            return;
        }
        // Graded attempt recorded — freeze the answers. Only Retake (below)
        // unlocks, by rendering a fresh form.
        lockQuiz(el, quiz);

        let s = 'Score: ' + data.score + ' / ' + data.max_score;
        if (data.best_score != null) s += ' · Best: ' + data.best_score;
        scoreEl.textContent = s;

        const actions = actionsBox;
        let pill = actions.querySelector('.uwq-status');
        if (!pill) {
            pill = document.createElement('span');
            pill.className = 'uwq-status';
            actions.insertBefore(pill, scoreEl);
        }
        const passed = !!data.passed;
        pill.classList.toggle('is-pass', passed);
        pill.classList.toggle('is-fail', !passed);
        pill.textContent = passed ? 'Passed' : 'Failed';
        let hint = actions.querySelector('.uwq-hint');
        if (!passed) {
            if (!hint) { hint = document.createElement('p'); hint.className = 'uwq-hint'; actions.appendChild(hint); }
            const need = Math.round((data.pass_threshold || 0.9) * 100);
            hint.textContent = 'You need at least ' + need + '% to complete this lesson — try again.';
        } else if (hint) { hint.remove(); }

        const btn = el.querySelector('.uwq-submit');
        btn.disabled = false;
        btn.textContent = 'Retake';
        btn.type = 'button';
        // Attempt limits: no retake once attempts run out; note the cooldown
        // otherwise (the server enforces both on submit regardless).
        let gate = actions.querySelector('.uwq-gate');
        if (gate) gate.remove();
        if (quiz.max_attempts && data.attempts_left != null) {
            const at = actions.querySelector('.uwq-attempts');
            if (at) at.textContent = 'Attempts used: ' + (quiz.max_attempts - data.attempts_left) + ' / ' + quiz.max_attempts;
        }
        if (data.attempts_left === 0) {
            btn.style.display = 'none';
            gate = document.createElement('p');
            gate.className = 'uwq-gate';
            gate.textContent = 'No attempts remaining for this quiz.';
            actions.appendChild(gate);
        } else if (data.cooldown_seconds > 0 && !passed) {
            gate = document.createElement('p');
            gate.className = 'uwq-gate';
            gate.textContent = 'You can try again in about ' + Math.max(1, Math.ceil(data.cooldown_seconds / 60)) + ' min.';
            actions.appendChild(gate);
        }
        btn.onclick = () => {
            // Preserve typed code and reflection text across a retake — coders
            // iterate on the same solution, and reflections stay viewable and
            // editable. Other question types reset to blank as before.
            const prev = collect(el, quiz);
            const keepDraft = {};
            (quiz.questions || []).forEach(q => {
                if ((q.question_type === 'coding' || q.question_type === 'reflection') && (q.id in prev)) {
                    keepDraft[q.id] = prev[q.id];
                }
            });
            renderQuiz(el, quiz, Object.keys(keepDraft).length ? keepDraft : undefined);
        };

        if (data.progress) {
            document.dispatchEvent(new CustomEvent('uwq-progress', { detail: data.progress }));
        }
    }

    function renderCodeResults(qEl, r) {
        const box = qEl.querySelector('.uwq-code-results');
        if (!box) return;
        box.style.display = 'block';
        let h = '';
        if (r.runner_error) {
            h += '<div class="uwq-code-banner is-err">⚠ ' + esc(r.runner_error) + '</div>';
        }
        if (r.compile_output) {
            h += '<div class="uwq-code-label">Compiler output</div><pre class="uwq-code-pre is-err">' + esc(r.compile_output) + '</pre>';
        }
        if (Array.isArray(r.tests)) {
            const expected = Array.isArray(r.tests_expected) ? r.tests_expected : null;
            r.tests.forEach((tc, i) => {
                h += '<div class="uwq-code-test ' + (tc.passed ? 'is-pass' : 'is-fail') + '">'
                    + '<div class="uwq-code-test-head">Test ' + (i + 1) + ' · '
                    + (tc.passed ? '<span class="uwq-ok">Passed</span>' : '<span class="uwq-no">Failed</span>') + '</div>';
                if (tc.stdout) h += '<div class="uwq-code-label">Your output</div><pre class="uwq-code-pre">' + esc(tc.stdout) + '</pre>';
                if (tc.stderr) h += '<div class="uwq-code-label">Errors</div><pre class="uwq-code-pre is-err">' + esc(tc.stderr) + '</pre>';
                if (expected && expected[i] != null) h += '<div class="uwq-code-label">Expected</div><pre class="uwq-code-pre is-exp">' + esc(expected[i]) + '</pre>';
                h += '</div>';
            });
        }
        box.innerHTML = h || '<div class="uwq-code-banner">No output.</div>';
    }

    // Shared text/image choice highlighting (reveal mode vs own-pick-only mode).
    function paintChoice(qEl, r, optSel, inputSel) {
        const correctIds = r.correct_option_ids;
        const reveal = Array.isArray(correctIds);
        qEl.querySelectorAll(optSel).forEach(opt => {
            const inp = opt.querySelector(inputSel);
            if (!inp) return;
            const val = parseInt(inp.value);
            opt.classList.remove('opt-correct', 'opt-chosen-wrong');
            if (reveal) {
                if (correctIds.indexOf(val) >= 0) opt.classList.add('opt-correct');
                if (inp.checked && correctIds.indexOf(val) < 0) opt.classList.add('opt-chosen-wrong');
            } else if (inp.checked) {
                opt.classList.add(r.correct ? 'opt-correct' : 'opt-chosen-wrong');
            }
        });
    }

    function init() {
        injectStyles();
        document.querySelectorAll('.uw-quiz-embed[data-quiz-id]').forEach(hydrate);
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
    window.UWQuiz = { init: init };
})();
