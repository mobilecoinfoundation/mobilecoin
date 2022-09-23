import glob
import json
import os
import sys
from collections import defaultdict
from flask import Flask, render_template, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
    last_slot_index = list(reversed(sorted(app.config['slots_by_index'].keys())))[0]
    return redirect(url_for('slot', slot_index=last_slot_index))


@app.route('/slot/<int:slot_index>')
def slot(slot_index):
    available_nodes = list(sorted(app.config['slots_by_index'].get(slot_index, {})))
    if not available_nodes:
        return 'No data for slot'
    return redirect(url_for('slot_node', slot_index=slot_index, node_id=available_nodes[0]))


@app.route('/slot/<int:slot_index>/<node_id>')
def slot_node(slot_index, node_id):
    slot_msgs = app.config['slots_by_index'][slot_index][node_id]
    return redirect(url_for('slot_node_msg', slot_index=slot_index, node_id=node_id, msg_index=len(slot_msgs)-1))


@app.route('/slot/<int:slot_index>/<node_id>/<int:msg_index>')
def slot_node_msg(slot_index, node_id, msg_index):
    slot_msgs = app.config['slots_by_index'][slot_index][node_id]
    slot = slot_msgs[msg_index]
    return render_template(
        'slot.html',
        slot=slot,
        slot_index=slot_index,
        node_id=node_id,
        msg_index=msg_index,
        highest_msg_index=len(slot_msgs) - 1,
        available_nodes=list(sorted(app.config['slots_by_index'][slot_index].keys())),
    )


if __name__ == '__main__':
    try:
        state_jsons_dir = sys.argv[1]
    except IndexError:
        print(f'Usage: {sys.argv[0]} [state jsons directory]')
        sys.exit(1)

    slots_by_index = defaultdict(dict)
    unique_node_ids = set()
    num_slots = 0
    for filename in sorted(glob.glob(os.path.join(state_jsons_dir, '**/*.json'), recursive=True)):
        data = json.load(open(filename))
        state = json.loads(data['state'])

        node_id = state['node_id']['responder_id']
        slot_index = state['slot_index']

        slots_by_index[slot_index].setdefault(node_id, [])
        slots_by_index[slot_index][node_id].append(state)
        unique_node_ids.add(node_id)
        num_slots += 1

    print(f'Loaded total of {num_slots} slot states from {len(unique_node_ids)} nodes')

    app.config['slots_by_index'] = slots_by_index
    app.run()
