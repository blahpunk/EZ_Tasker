from flask import Flask, request, jsonify, render_template
import json
import os

app = Flask(__name__)

# Path to the JSON file
TASKS_FILE = 'tasks.json'

# Load tasks from the JSON file
def load_tasks():
    if os.path.exists(TASKS_FILE):
        with open(TASKS_FILE, 'r') as file:
            return json.load(file)
    return []

# Save tasks to the JSON file
def save_tasks(tasks):
    with open(TASKS_FILE, 'w') as file:
        json.dump(tasks, file, indent=4)

# In-memory task storage
tasks = load_tasks()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/tasks', methods=['GET'])
def get_tasks():
    return jsonify(tasks)

@app.route('/tasks', methods=['POST'])
def add_task():
    task = request.json
    task['index'] = len(tasks)  # Assign the current length as the index
    tasks.append(task)
    save_tasks(tasks)
    return jsonify(task), 201


@app.route('/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    task = request.json
    task['index'] = tasks[task_id]['index']  # Retain the original index
    tasks[task_id] = task
    save_tasks(tasks)
    return jsonify(task)


@app.route('/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    tasks.pop(task_id)
    save_tasks(tasks)
    return '', 204

@app.route('/tasks/order', methods=['POST'])
def save_order():
    global tasks
    ordered_tasks = request.json
    for i, task in enumerate(ordered_tasks):
        task['index'] = i  # Update the index for each task based on new order
    tasks = ordered_tasks
    save_tasks(tasks)
    return '', 204


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5151)
