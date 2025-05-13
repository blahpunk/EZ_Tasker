document.addEventListener('DOMContentLoaded', function () {
    const taskList = document.getElementById('taskList');
    const addTaskBtn = document.getElementById('addTaskBtn');
    const saveTaskBtn = document.getElementById('saveTaskBtn');
    const taskForm = document.getElementById('taskForm');
    const taskTitleInput = document.getElementById('taskTitle');
    const taskDueDateInput = document.getElementById('taskDueDate');
    const editorContainer = document.getElementById('editor-container');
    let editor = new Quill(editorContainer, { theme: 'snow' });

    let currentEditingTask = null;
    let tasks = [];

    new Sortable(taskList, {
        animation: 150,
        ghostClass: 'sortable-ghost',
        handle: '.drag-handle',
        delay: 150,
        delayOnTouchOnly: true,
        scroll: true,
        onStart: () => document.body.style.overflow = 'hidden',
        onEnd: () => {
            document.body.style.overflow = '';
            saveTaskOrder();
        }
    });

    addTaskBtn.addEventListener('click', () => {
        taskForm.style.display = 'block';
        taskTitleInput.value = '';
        taskDueDateInput.value = '';
        editor.setText('');
        currentEditingTask = null;
    });

    saveTaskBtn.addEventListener('click', async () => {
        const taskTitle = taskTitleInput.value.trim();
        const taskDescription = editor.root.innerHTML.trim();
        const taskDueDate = taskDueDateInput.value ? new Date(taskDueDateInput.value).toLocaleDateString() : '';
        const timestamp = new Date().toLocaleString();

        if (taskTitle && taskDescription) {
            if (currentEditingTask) {
                tasks[currentEditingTask.index] = {
                    ...tasks[currentEditingTask.index],
                    title: taskTitle,
                    description: taskDescription,
                    dueDate: taskDueDate,
                    timestamp: timestamp
                };
                await updateTask(currentEditingTask.index, tasks[currentEditingTask.index]);
            } else {
                const newTask = { title: taskTitle, description: taskDescription, dueDate: taskDueDate, timestamp: timestamp };
                tasks.unshift(newTask);
                await addTask(newTask);
            }
            resetForm();
            loadTasks();
        } else {
            alert('Please provide both a title and a description for the task.');
        }
    });

    function resetForm() {
        taskTitleInput.value = '';
        taskDueDateInput.value = '';
        editor.setText('');
        taskForm.style.display = 'none';
        currentEditingTask = null;
    }

    function addTaskToUI(task, index) {
        const taskItem = document.createElement('div');
        taskItem.className = 'task-item';
        taskItem.setAttribute('data-id', index);

        const taskTitle = document.createElement('h2');
        taskTitle.innerText = task.title;

        const arrow = document.createElement('span');
        arrow.className = 'expand-arrow';
        arrow.innerText = '';
        taskTitle.appendChild(arrow);

        const dragHandle = document.createElement('div');
        dragHandle.className = 'drag-handle';
        dragHandle.innerText = '⠿';

        const taskDesc = document.createElement('p');
        taskDesc.className = 'task-desc collapsed';
        taskDesc.innerHTML = task.description;

        const taskMeta = document.createElement('div');
        taskMeta.className = 'task-meta';
        taskMeta.innerHTML = `<span>Created: ${task.timestamp}</span>${task.dueDate ? `<span>Due: ${task.dueDate}</span>` : ''}`;

        const actions = document.createElement('div');
        actions.className = 'actions';
        const editBtn = document.createElement('button');
        editBtn.innerText = 'Edit';
        const deleteBtn = document.createElement('button');
        deleteBtn.innerText = 'Delete';

        actions.appendChild(editBtn);
        actions.appendChild(deleteBtn);

        taskItem.appendChild(dragHandle);
        taskItem.appendChild(taskTitle);
        taskItem.appendChild(taskDesc);
        taskItem.appendChild(taskMeta);
        taskItem.appendChild(actions);

        taskList.appendChild(taskItem);

        requestAnimationFrame(() => {
            const lineHeight = parseFloat(getComputedStyle(taskDesc).lineHeight) || 20;
            const maxLines = 3;
            const maxHeight = lineHeight * maxLines;

            if (taskDesc.scrollHeight > maxHeight + 2) {
                arrow.innerText = '▼';
                taskItem.classList.add('expandable');
            } else {
                arrow.style.display = 'none';
            }
        });

        taskItem.addEventListener('click', () => {
            if (!taskItem.classList.contains('expandable')) return;

            const expanded = taskDesc.classList.toggle('expanded');
            taskDesc.classList.toggle('collapsed', !expanded);
            arrow.innerText = expanded ? '▲' : '▼';
        });

        editBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            editTask(task, index);
        });

        deleteBtn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const confirmDelete = confirm("Are you sure you want to delete this task?");
            if (confirmDelete) {
                await deleteTask(index);
                loadTasks();
            }
        });
    }

    function editTask(task, index) {
        taskTitleInput.value = task.title;
        taskDueDateInput.value = task.dueDate ? new Date(task.dueDate).toISOString().split('T')[0] : '';
        editor.root.innerHTML = task.description;
        taskForm.style.display = 'block';
        currentEditingTask = { index: index };
    }

    async function loadTasks() {
        taskList.innerHTML = '';
        const response = await fetch('api/tasks');
        tasks = await response.json();
        tasks.forEach((task, index) => addTaskToUI(task, index));
    }

    async function saveTaskOrder() {
        const orderedTasks = [];
        taskList.querySelectorAll('.task-item').forEach((taskItem, newIndex) => {
            const id = taskItem.getAttribute('data-id');
            tasks[id].index = newIndex;
            orderedTasks.push(tasks[id]);
        });
        tasks = orderedTasks;
        await fetch('api/tasks/order', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(orderedTasks)
        });
    }

    async function addTask(task) {
        await fetch('api/tasks', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(task)
        });
    }

    async function updateTask(index, task) {
        await fetch(`api/tasks/${index}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(task)
        });
    }

    async function deleteTask(index) {
        tasks.splice(index, 1);
        await fetch(`api/tasks/${index}`, {
            method: 'DELETE'
        });
    }

    loadTasks();
});
