document.addEventListener('DOMContentLoaded', function () {
    const taskList = document.getElementById('taskList');
    const addTaskBtn = document.getElementById('addTaskBtn');
    const saveTaskBtn = document.getElementById('saveTaskBtn');
    const taskForm = document.getElementById('taskForm');
    const taskTitleInput = document.getElementById('taskTitle');
    const taskDueDateInput = document.getElementById('taskDueDate');
    const editorContainer = document.getElementById('editor-container');
    let editor = new Quill(editorContainer, {
        theme: 'snow'
    });

    let currentEditingTask = null;
    let tasks = [];

    // Initialize Sortable.js for drag-and-drop functionality
    new Sortable(taskList, {
        animation: 150,
        ghostClass: 'sortable-ghost',
        handle: '.task-item',
        delay: 150, // Delay before drag starts
        delayOnTouchOnly: true, // Only apply delay on touch devices
        onStart: function () {
            document.body.style.overflow = 'hidden';
        },
        onEnd: function () {
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
                // Update existing task
                tasks[currentEditingTask.index] = { ...tasks[currentEditingTask.index], title: taskTitle, description: taskDescription, dueDate: taskDueDate, timestamp: timestamp };
                await updateTask(currentEditingTask.index, tasks[currentEditingTask.index]);
            } else {
                // Add new task at the top
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

        taskItem.appendChild(taskTitle);
        taskItem.appendChild(taskDesc);
        taskItem.appendChild(taskMeta);
        taskItem.appendChild(actions);

        taskList.appendChild(taskItem);

        editBtn.addEventListener('click', () => {
            editTask(task, index);
        });

        deleteBtn.addEventListener('click', async () => {
            await deleteTask(index);
            loadTasks();
        });

        // Toggle description expansion
        taskItem.addEventListener('click', () => {
            taskDesc.classList.toggle('collapsed');
            taskDesc.classList.toggle('expanded');
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
        taskList.innerHTML = ''; // Clear the task list
        const response = await fetch('/tasks');
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
        await fetch('/tasks/order', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(orderedTasks)
        });
    }

    async function addTask(task) {
        await fetch('/tasks', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(task)
        });
    }

    async function updateTask(index, task) {
        await fetch(`/tasks/${index}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(task)
        });
    }

    async function deleteTask(index) {
        tasks.splice(index, 1);
        await fetch(`/tasks/${index}`, {
            method: 'DELETE'
        });
    }

    loadTasks();
});
