// /var/www/tasklist/static/js/scripts.js

document.addEventListener('DOMContentLoaded', function () {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

    const taskList = document.getElementById('taskList');
    const noTasksMessage = document.getElementById('noTasksMessage');

    const addTaskBtn = document.getElementById('addTaskBtn');
    const saveTaskBtn = document.getElementById('saveTaskBtn');
    const cancelTaskBtn = document.getElementById('cancelTaskBtn');

    const taskForm = document.getElementById('taskForm');
    const taskTitleInput = document.getElementById('taskTitle');
    const taskDueDateInput = document.getElementById('taskDueDate');
    const taskPriorityInput = document.getElementById('taskPriority');
    const taskTagsInput = document.getElementById('taskTags');

    const searchInput = document.getElementById('searchInput');
    const statusSelect = document.getElementById('statusSelect');
    const specialSelect = document.getElementById('specialSelect');
    const sortSelect = document.getElementById('sortSelect');
    const hideCompleted = document.getElementById('hideCompleted');

    const editorContainer = document.getElementById('editor-container');
    const editor = new Quill(editorContainer, { theme: 'snow' });

    function setEditorHtml(html) {
        editor.setContents([]);
        if (html && html.trim()) {
            editor.clipboard.dangerouslyPasteHTML(html);
        }
    }

    let tasks = [];
    let currentEditingId = null;
    let suppressExpandClick = false;

    const DRAFT_KEY = 'ez_tasker_draft_v2';

    function apiUrl(path) {
        // keep relative; reverse proxy should handle it
        return path.startsWith('/') ? path : `/${path}`;
    }

    function headersJson() {
        return {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        };
    }

    function isManualSort() {
        return (sortSelect.value || 'manual') === 'manual' &&
               (specialSelect.value || '') === '' &&
               (searchInput.value || '').trim() === '' &&
               (statusSelect.value || 'all') === 'all' &&
               hideCompleted.checked === false;
    }

    function parseTagsInput(str) {
        return (str || '')
            .split(',')
            .map(s => s.trim())
            .filter(Boolean);
    }

    function normalizeQuillLists(html) {
        const container = document.createElement('div');
        container.innerHTML = html || '';

        container.querySelectorAll('ol').forEach((ol) => {
            const children = Array.from(ol.children).filter((el) => el.tagName === 'LI');
            if (!children.length) return;

            const frag = document.createDocumentFragment();
            let currentList = null;
            let currentType = '';

            children.forEach((li) => {
                const listType = li.getAttribute('data-list') === 'bullet' ? 'ul' : 'ol';
                if (!currentList || currentType !== listType) {
                    currentList = document.createElement(listType);
                    frag.appendChild(currentList);
                    currentType = listType;
                }
                li.removeAttribute('data-list');
                currentList.appendChild(li);
            });

            ol.replaceWith(frag);
        });

        const topLevel = Array.from(container.childNodes).filter((node) => {
            return !(node.nodeType === Node.TEXT_NODE && !(node.textContent || '').trim());
        });
        const isParagraphOnly = topLevel.length > 0 && topLevel.every((node) => {
            return node.nodeType === Node.ELEMENT_NODE && node.tagName === 'P';
        });
        if (isParagraphOnly) {
            const frag = document.createDocumentFragment();
            topLevel.forEach((node, idx) => {
                const p = node;
                const htmlVal = (p.innerHTML || '').trim().toLowerCase();
                const isEmpty = !htmlVal || htmlVal === '<br>';
                if (!isEmpty) {
                    while (p.firstChild) {
                        frag.appendChild(p.firstChild);
                    }
                }
                if (idx < topLevel.length - 1) {
                    frag.appendChild(document.createElement('br'));
                }
            });
            container.replaceChildren(frag);
        }

        return container.innerHTML;
    }

    function setHidden(el, hidden) {
        if (!el) return;
        el.classList.toggle('is-hidden', !!hidden);
    }

    function setFormVisible(visible) {
        setHidden(taskForm, !visible);
    }

    function resetForm() {
        taskTitleInput.value = '';
        taskDueDateInput.value = '';
        taskPriorityInput.value = '1';
        taskTagsInput.value = '';
        setEditorHtml('');
        currentEditingId = null;
        setFormVisible(false);
        clearDraft();
    }

    function saveDraft() {
        const draft = {
            title: taskTitleInput.value || '',
            due_date: taskDueDateInput.value || '',
            priority: taskPriorityInput.value || '1',
            tags: taskTagsInput.value || '',
            description_html: normalizeQuillLists(editor.root.innerHTML || '')
        };
        localStorage.setItem(DRAFT_KEY, JSON.stringify(draft));
    }

    function loadDraft() {
        try {
            const raw = localStorage.getItem(DRAFT_KEY);
            if (!raw) return false;
            const d = JSON.parse(raw);
            if (!d) return false;
            taskTitleInput.value = d.title || '';
            taskDueDateInput.value = d.due_date || '';
            taskPriorityInput.value = String(d.priority ?? '1');
            taskTagsInput.value = d.tags || '';
            setEditorHtml(d.description_html || '');
            return true;
        } catch (_e) {
            return false;
        }
    }

    function clearDraft() {
        localStorage.removeItem(DRAFT_KEY);
    }

    function debounce(fn, ms) {
        let t = null;
        return (...args) => {
            clearTimeout(t);
            t = setTimeout(() => fn(...args), ms);
        };
    }

    const debouncedSaveDraft = debounce(saveDraft, 250);
    taskTitleInput.addEventListener('input', debouncedSaveDraft);
    taskDueDateInput.addEventListener('input', debouncedSaveDraft);
    taskPriorityInput.addEventListener('change', debouncedSaveDraft);
    taskTagsInput.addEventListener('input', debouncedSaveDraft);
    editor.on('text-change', debouncedSaveDraft);

    const sortable = new Sortable(taskList, {
        animation: 150,
        ghostClass: 'sortable-ghost',
        handle: '.drag-handle',
        delay: 150,
        delayOnTouchOnly: true,
        scroll: true,
        onStart: () => {
            document.body.classList.add('no-scroll');
            suppressExpandClick = true;
        },
        onEnd: async () => {
            document.body.classList.remove('no-scroll');
            setTimeout(() => { suppressExpandClick = false; }, 0);

            if (!isManualSort()) {
                // If not in manual mode, revert by reloading
                await loadTasks();
                return;
            }

            await saveTaskOrder();
        }
    });

    function setNoTasksMessage() {
        const isEmpty = tasks.length === 0;
        setHidden(noTasksMessage, !isEmpty);
    }

    function priorityLabel(p) {
        if (p === 2) return { text: 'High', cls: 'priority-high' };
        if (p === 0) return { text: 'Low', cls: 'priority-low' };
        return { text: 'Medium', cls: 'priority-med' };
    }

    function dueBadge(due_date, completed) {
        if (!due_date || completed) return null;
        const today = new Date();
        today.setHours(0,0,0,0);

        const due = new Date(due_date + 'T00:00:00');
        const diffDays = Math.floor((due - today) / (24 * 60 * 60 * 1000));

        if (diffDays < 0) return { text: 'Overdue', cls: 'due-overdue' };
        if (diffDays <= 7) return { text: 'Due soon', cls: 'due-soon' };
        return null;
    }

    function fmtDate(iso) {
        if (!iso) return '';
        try {
            const d = new Date(iso.includes('T') ? iso : (iso + 'T00:00:00'));
            return d.toLocaleString();
        } catch (_e) {
            return iso;
        }
    }

    function fmtDue(isoDate) {
        if (!isoDate) return '';
        try {
            const d = new Date(isoDate + 'T00:00:00');
            return d.toLocaleDateString();
        } catch (_e) {
            return isoDate;
        }
    }

    function escapeText(s) {
        const div = document.createElement('div');
        div.innerText = s ?? '';
        return div.innerHTML;
    }

    function addTaskToUI(task) {
        const taskItem = document.createElement('div');
        taskItem.className = 'task-item';
        taskItem.setAttribute('data-id', task.id);

        const top = document.createElement('div');
        top.className = 'task-top';

        const dragHandle = document.createElement('div');
        dragHandle.className = 'drag-handle';
        dragHandle.innerText = '⠿';

        const complete = document.createElement('input');
        complete.type = 'checkbox';
        complete.className = 'complete-toggle';
        complete.checked = !!task.completed;

        const headline = document.createElement('div');
        headline.className = 'task-headline';

        const titleRow = document.createElement('div');
        titleRow.className = 'task-title-row';

        const title = document.createElement('h2');
        title.className = 'task-title';
        title.innerText = task.title || '';
        if (task.completed) title.classList.add('completed');

        const badges = document.createElement('div');
        badges.className = 'badges';

        const p = priorityLabel(Number(task.priority));
        const prBadge = document.createElement('span');
        prBadge.className = `badge ${p.cls}`;
        prBadge.innerText = `Priority: ${p.text}`;

        badges.appendChild(prBadge);

        const db = dueBadge(task.due_date, task.completed);
        if (db) {
            const dueB = document.createElement('span');
            dueB.className = `badge ${db.cls}`;
            dueB.innerText = db.text;
            badges.appendChild(dueB);
        }

        const arrow = document.createElement('span');
        arrow.className = 'expand-arrow';
        arrow.innerText = '';

        titleRow.appendChild(title);
        titleRow.appendChild(badges);
        titleRow.appendChild(arrow);

        const desc = document.createElement('div');
        desc.className = 'task-desc collapsed';
        desc.innerHTML = task.description_html || '';

        const meta = document.createElement('div');
        meta.className = 'task-meta';
        const duePart = task.due_date ? `<span>Due: ${escapeText(fmtDue(task.due_date))}</span>` : '';
        meta.innerHTML = `<span>Created: ${escapeText(fmtDate(task.created_at))}</span>${duePart}<span>Updated: ${escapeText(fmtDate(task.updated_at))}</span>`;

        const tagsWrap = document.createElement('div');
        tagsWrap.className = 'tags';
        const tagList = Array.isArray(task.tags) ? task.tags : [];
        if (tagList.length) {
            tagList.forEach(t => {
                const chip = document.createElement('span');
                chip.className = 'tag';
                chip.innerText = t;
                tagsWrap.appendChild(chip);
            });
        }

        const actions = document.createElement('div');
        actions.className = 'actions';

        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-secondary';
        editBtn.innerText = 'Edit';

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn btn-danger';
        deleteBtn.innerText = 'Delete';

        actions.appendChild(editBtn);
        actions.appendChild(deleteBtn);

        headline.appendChild(titleRow);

        top.appendChild(dragHandle);
        top.appendChild(complete);
        top.appendChild(headline);

        taskItem.appendChild(top);
        taskItem.appendChild(desc);
        taskItem.appendChild(meta);
        if (tagList.length) taskItem.appendChild(tagsWrap);
        taskItem.appendChild(actions);

        taskList.appendChild(taskItem);

        requestAnimationFrame(() => {
            const lineHeight = parseFloat(getComputedStyle(desc).lineHeight) || 20;
            const maxLines = 3;
            const maxHeight = lineHeight * maxLines;
            if (desc.scrollHeight > maxHeight + 2) {
                arrow.innerText = '▼';
                taskItem.classList.add('expandable');
            } else {
                setHidden(arrow, true);
            }
        });

        taskItem.addEventListener('click', () => {
        if (suppressExpandClick) return;
        if (!taskItem.classList.contains('expandable')) return;

            const expanded = desc.classList.toggle('expanded');
            desc.classList.toggle('collapsed', !expanded);
            arrow.innerText = expanded ? '▲' : '▼';
        });

        complete.addEventListener('click', async (e) => {
            e.stopPropagation();
            const newVal = complete.checked;
            await updateTask(task.id, {
                completed: newVal
            });
            await loadTasks();
        });

        editBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            editTask(task);
        });

        deleteBtn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const confirmDelete = confirm("Delete this task?");
            if (!confirmDelete) return;
            await deleteTask(task.id);
            await loadTasks();
        });
    }

    function editTask(task) {
        currentEditingId = task.id;
        setFormVisible(true);

        taskTitleInput.value = task.title || '';
        taskDueDateInput.value = task.due_date || '';
        taskPriorityInput.value = String(task.priority ?? 1);
        taskTagsInput.value = Array.isArray(task.tags) ? task.tags.join(', ') : '';
        setEditorHtml(task.description_html || '');

        saveDraft();
        taskTitleInput.focus();
    }

    async function loadTasks() {
        const q = (searchInput.value || '').trim();
        const status = statusSelect.value || 'all';
        const special = specialSelect.value || '';
        const sort = sortSelect.value || 'manual';
        const hide = hideCompleted.checked ? '1' : '0';

        const params = new URLSearchParams();
        if (q) params.set('q', q);
        if (status) params.set('status', status);
        if (special) params.set('special', special);
        if (sort) params.set('sort', sort);
        if (hide === '1') params.set('hide_completed', hide);

        taskList.innerHTML = '';
        setHidden(noTasksMessage, true);

        const res = await fetch(apiUrl(`/api/v1/tasks?${params.toString()}`));
        if (!res.ok) {
            setHidden(noTasksMessage, false);
            noTasksMessage.innerText = 'Failed to load tasks.';
            return;
        }

        tasks = await res.json();
        tasks.forEach(addTaskToUI);
        setNoTasksMessage();

        // Enable/disable sorting based on current mode
        sortable.option("disabled", !isManualSort());
    }

    async function saveTaskOrder() {
        const orderedIds = [];
        taskList.querySelectorAll('.task-item').forEach((taskItem) => {
            orderedIds.push(taskItem.getAttribute('data-id'));
        });

        await fetch(apiUrl('/api/v1/tasks/reorder'), {
            method: 'POST',
            headers: headersJson(),
            body: JSON.stringify({ ordered_ids: orderedIds })
        });
    }

    async function createTask(payload) {
        const res = await fetch(apiUrl('/api/v1/tasks'), {
            method: 'POST',
            headers: headersJson(),
            body: JSON.stringify(payload)
        });
        return res;
    }

    async function updateTask(id, payload) {
        const res = await fetch(apiUrl(`/api/v1/tasks/${encodeURIComponent(id)}`), {
            method: 'PUT',
            headers: headersJson(),
            body: JSON.stringify(payload)
        });
        return res;
    }

    async function deleteTask(id) {
        const res = await fetch(apiUrl(`/api/v1/tasks/${encodeURIComponent(id)}`), {
            method: 'DELETE',
            headers: { 'X-CSRF-Token': csrfToken }
        });
        return res;
    }

    addTaskBtn.addEventListener('click', () => {
        setFormVisible(true);
        currentEditingId = null;

        const hadDraft = loadDraft();
        if (!hadDraft) {
            taskTitleInput.value = '';
            taskDueDateInput.value = '';
            taskPriorityInput.value = '1';
            taskTagsInput.value = '';
            setEditorHtml('');
        }

        taskTitleInput.focus();
    });

    cancelTaskBtn.addEventListener('click', () => {
        resetForm();
    });

    saveTaskBtn.addEventListener('click', async () => {
        const title = (taskTitleInput.value || '').trim();
        const description_html = normalizeQuillLists((editor.root.innerHTML || '').trim());
        const due_date = (taskDueDateInput.value || '').trim() || null;
        const priority = Number(taskPriorityInput.value || 1);
        const tags = parseTagsInput(taskTagsInput.value);

        if (!title) {
            alert('Title is required.');
            return;
        }

        const payload = { title, description_html, due_date, priority, tags };

        if (currentEditingId) {
            const res = await updateTask(currentEditingId, payload);
            if (!res.ok) {
                alert('Failed to update task.');
                return;
            }
        } else {
            const res = await createTask(payload);
            if (!res.ok) {
                alert('Failed to create task.');
                return;
            }
        }

        resetForm();
        await loadTasks();
    });

    const debouncedLoad = debounce(loadTasks, 200);
    searchInput.addEventListener('input', debouncedLoad);
    statusSelect.addEventListener('change', loadTasks);
    specialSelect.addEventListener('change', loadTasks);
    sortSelect.addEventListener('change', loadTasks);
    hideCompleted.addEventListener('change', loadTasks);

    // Initial load
    loadTasks();
});
