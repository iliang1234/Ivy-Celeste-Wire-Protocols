import json
import os
import threading
import time
import random
from enum import Enum
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
import socket
import struct
import pickle

class NodeState(Enum):
    FOLLOWER = 1
    CANDIDATE = 2
    LEADER = 3

@dataclass
class LogEntry:
    term: int
    command: bytes
    index: int

class RaftNode:
    def __init__(self, node_id: int, config_path: str):
        with open(config_path) as f:
            self.config = json.load(f)
            
        self.node_id = node_id
        self.node_config = next(r for r in self.config['replicas'] if r['id'] == node_id)
        self.state = NodeState.FOLLOWER
        self.current_term = 0
        self.voted_for: Optional[int] = None
        self.log: List[LogEntry] = []
        self.commit_index = -1
        self.last_applied = -1
        self.next_index: Dict[int, int] = {}
        self.match_index: Dict[int, int] = {}
        self.leader_id: Optional[int] = None
        
        # Initialize empty log
        self.log = []
        
        base_timeout = self.config['election_timeout_ms'] / 1000
        self.election_timeout = base_timeout + random.uniform(0, base_timeout)
        self.heartbeat_interval = self.config['heartbeat_interval_ms'] / 1000
        
        self.last_heartbeat = time.time()
        self.votes_received: Set[int] = set()
        
        self.state_lock = threading.Lock()
        self.running = True
        
        # Get script directory for relative paths
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Initialize persistent storage
        self.data_dir = os.path.join(self.script_dir, "data", f"replica_{node_id}")
        os.makedirs(self.data_dir, exist_ok=True)
        self.load_persistent_state()
        
        # Initialize sockets
        self.replica_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.replica_socket.bind((self.node_config['host'], self.node_config['replica_port']))
        
        # Start background threads
        threading.Thread(target=self.run_election_timer, daemon=True).start()
        threading.Thread(target=self.handle_replica_messages, daemon=True).start()

    def load_persistent_state(self):
        """Load persistent state from disk"""
        state_file = os.path.join(self.data_dir, 'state.json')
        log_file = os.path.join(self.data_dir, 'log.pickle')
        
        # Load state if exists, otherwise use defaults
        if os.path.exists(state_file):
            try:
                with open(state_file) as f:
                    state = json.load(f)
                    self.current_term = state['current_term']
                    self.voted_for = state['voted_for']
            except (json.JSONDecodeError, KeyError):
                # Reset to defaults if file is corrupted
                self.current_term = 0
                self.voted_for = None
        
        # Load log if exists, otherwise use empty log
        if os.path.exists(log_file):
            try:
                with open(log_file, 'rb') as f:
                    self.log = pickle.load(f)
            except (pickle.UnpicklingError, EOFError):
                # Reset to empty log if file is corrupted
                self.log = []

    def save_persistent_state(self):
        """Save persistent state to disk"""
        state_file = os.path.join(self.data_dir, 'state.json')
        log_file = os.path.join(self.data_dir, 'log.pickle')
        
        state = {
            'current_term': self.current_term,
            'voted_for': self.voted_for
        }
        
        with open(state_file, 'w') as f:
            json.dump(state, f)
            
        with open(log_file, 'wb') as f:
            pickle.dump(self.log, f)

    def run_election_timer(self):
        """Run the election timer thread"""
        while self.running:
            with self.state_lock:
                if (self.state != NodeState.LEADER and 
                    time.time() - self.last_heartbeat > self.election_timeout):
                    self.start_election()
                    # Reset election timeout with new random value
                    base_timeout = self.config['election_timeout_ms'] / 1000
                    self.election_timeout = base_timeout + random.uniform(0, base_timeout)
            time.sleep(0.05)  # Small sleep to prevent busy waiting

    def start_election(self):
        """Start a new election"""
        self.state = NodeState.CANDIDATE
        self.current_term += 1
        self.voted_for = self.node_id
        self.votes_received = {self.node_id}
        self.last_heartbeat = time.time()
        self.save_persistent_state()
        
        print(f"Node {self.node_id} starting election for term {self.current_term}")
        
        # Send RequestVote RPCs
        for replica in self.config['replicas']:
            if replica['id'] != self.node_id:
                print(f"Node {self.node_id} sending RequestVote to node {replica['id']}")
                self.send_request_vote(replica)

    def handle_replica_messages(self):
        """Handle incoming messages from other replicas"""
        while self.running:
            try:
                data, addr = self.replica_socket.recvfrom(65536)
                message = pickle.loads(data)
                
                if message['type'] == 'RequestVote':
                    self.handle_request_vote(message, addr)
                elif message['type'] == 'RequestVoteResponse':
                    self.handle_vote_response(message)
                elif message['type'] == 'AppendEntries':
                    self.handle_append_entries(message, addr)
                elif message['type'] == 'AppendEntriesResponse':
                    self.handle_append_entries_response(message)
            except Exception as e:
                print(f"Error handling replica message: {e}")

    def send_request_vote(self, target_replica):
        """Send RequestVote RPC to a target replica"""
        last_log_index = len(self.log) - 1
        last_log_term = self.log[last_log_index].term if self.log else 0
        
        message = {
            'type': 'RequestVote',
            'term': self.current_term,
            'candidate_id': self.node_id,
            'last_log_index': last_log_index,
            'last_log_term': last_log_term
        }
        
        self.replica_socket.sendto(
            pickle.dumps(message),
            (target_replica['host'], target_replica['replica_port'])
        )

    def handle_request_vote(self, message, addr):
        """Handle incoming RequestVote RPC"""
        with self.state_lock:
            print(f"Node {self.node_id} received RequestVote from node {message['candidate_id']} for term {message['term']}")
            
            if message['term'] < self.current_term:
                response = {
                    'type': 'RequestVoteResponse',
                    'term': self.current_term,
                    'vote_granted': False,
                    'from_id': self.node_id
                }
                print(f"Node {self.node_id} rejected vote: term {message['term']} < current_term {self.current_term}")
            else:
                if message['term'] > self.current_term:
                    print(f"Node {self.node_id} updating term: {self.current_term} -> {message['term']}")
                    self.current_term = message['term']
                    self.state = NodeState.FOLLOWER
                    self.voted_for = None
                    self.save_persistent_state()
                
                last_log_index = len(self.log) - 1
                last_log_term = self.log[last_log_index].term if self.log else 0
                
                if (self.voted_for is None or self.voted_for == message['candidate_id']) and \
                   (message['last_log_term'] > last_log_term or \
                    (message['last_log_term'] == last_log_term and \
                     message['last_log_index'] >= last_log_index)):
                    self.voted_for = message['candidate_id']
                    self.save_persistent_state()
                    response = {
                        'type': 'RequestVoteResponse',
                        'term': self.current_term,
                        'vote_granted': True,
                        'from_id': self.node_id
                    }
                    print(f"Node {self.node_id} granted vote to node {message['candidate_id']} for term {message['term']}")
                else:
                    response = {
                        'type': 'RequestVoteResponse',
                        'term': self.current_term,
                        'vote_granted': False,
                        'from_id': self.node_id
                    }
                    print(f"Node {self.node_id} rejected vote: already voted for {self.voted_for} in term {self.current_term}")
            
            self.replica_socket.sendto(pickle.dumps(response), addr)

    def handle_vote_response(self, message):
        """Handle vote response from other replicas"""
        with self.state_lock:
            print(f"Node {self.node_id} received vote response from node {message['from_id']}: granted={message['vote_granted']}")
            
            if self.state != NodeState.CANDIDATE:
                print(f"Node {self.node_id} ignoring vote: no longer a candidate")
                return
                
            if message['term'] > self.current_term:
                print(f"Node {self.node_id} stepping down: term {message['term']} > current_term {self.current_term}")
                self.current_term = message['term']
                self.state = NodeState.FOLLOWER
                self.voted_for = None
                self.save_persistent_state()
                return
            
            if message['vote_granted']:
                self.votes_received.add(message['from_id'])
                votes_needed = len(self.config['replicas']) // 2 + 1
                print(f"Node {self.node_id} received vote from {message['from_id']}: {len(self.votes_received)}/{votes_needed} votes")
                
                if len(self.votes_received) >= votes_needed:
                    print(f"Node {self.node_id} won election for term {self.current_term}")
                    self.become_leader()

    def become_leader(self):
        """Transition to leader state"""
        print(f"Node {self.node_id} becoming leader for term {self.current_term}")
        self.state = NodeState.LEADER
        self.leader_id = self.node_id
        self.next_index = {r['id']: len(self.log) for r in self.config['replicas']}
        self.match_index = {r['id']: -1 for r in self.config['replicas']}
        
        # Start sending heartbeats
        threading.Thread(target=self.send_heartbeats, daemon=True).start()

    def send_heartbeats(self):
        """Send periodic heartbeats to all followers"""
        while self.running and self.state == NodeState.LEADER:
            for replica in self.config['replicas']:
                if replica['id'] != self.node_id:
                    self.send_append_entries(replica['id'])
            time.sleep(self.heartbeat_interval)

    def send_append_entries(self, follower_id):
        """Send AppendEntries RPC to a follower"""
        next_idx = self.next_index[follower_id]
        prev_log_index = next_idx - 1
        prev_log_term = self.log[prev_log_index].term if prev_log_index >= 0 else 0
        
        entries = self.log[next_idx:] if next_idx < len(self.log) else []
        
        message = {
            'type': 'AppendEntries',
            'term': self.current_term,
            'leader_id': self.node_id,
            'prev_log_index': prev_log_index,
            'prev_log_term': prev_log_term,
            'entries': entries,
            'leader_commit': self.commit_index
        }
        
        target_replica = next(r for r in self.config['replicas'] if r['id'] == follower_id)
        self.replica_socket.sendto(
            pickle.dumps(message),
            (target_replica['host'], target_replica['replica_port'])
        )

    def handle_append_entries(self, message, addr):
        """Handle incoming AppendEntries RPC"""
        with self.state_lock:
            print(f"Node {self.node_id} received AppendEntries from node {message['leader_id']} for term {message['term']}")
            
            if message['term'] < self.current_term:
                response = {
                    'type': 'AppendEntriesResponse',
                    'term': self.current_term,
                    'success': False,
                    'from_id': self.node_id
                }
                print(f"Node {self.node_id} rejected AppendEntries: term {message['term']} < current_term {self.current_term}")
            else:
                # Always update term if leader's term is higher
                if message['term'] > self.current_term:
                    print(f"Node {self.node_id} updating term: {self.current_term} -> {message['term']}")
                    self.current_term = message['term']
                    self.voted_for = None
                    self.save_persistent_state()
                
                # Accept the leader
                self.state = NodeState.FOLLOWER
                self.leader_id = message['leader_id']
                self.last_heartbeat = time.time()
                print(f"Node {self.node_id} acknowledging leader {message['leader_id']} for term {message['term']}")
                
                # Check log consistency
                if message['prev_log_index'] >= len(self.log) or \
                   (message['prev_log_index'] >= 0 and \
                    self.log[message['prev_log_index']].term != message['prev_log_term']):
                    response = {
                        'type': 'AppendEntriesResponse',
                        'term': self.current_term,
                        'success': False,
                        'from_id': self.node_id
                    }
                else:
                    # Append new entries
                    if message['entries']:
                        self.log = self.log[:message['prev_log_index'] + 1]
                        self.log.extend(message['entries'])
                        self.save_persistent_state()
                    
                    # Update commit index
                    if message['leader_commit'] > self.commit_index:
                        self.commit_index = min(message['leader_commit'], len(self.log) - 1)
                    
                    response = {
                        'type': 'AppendEntriesResponse',
                        'term': self.current_term,
                        'success': True,
                        'from_id': self.node_id
                    }
            
            self.replica_socket.sendto(pickle.dumps(response), addr)

    def handle_append_entries_response(self, message):
        """Handle AppendEntries response from followers"""
        with self.state_lock:
            if self.state != NodeState.LEADER:
                return
                
            if message['term'] > self.current_term:
                self.current_term = message['term']
                self.state = NodeState.FOLLOWER
                self.voted_for = None
                self.save_persistent_state()
                return
            
            if message['success']:
                self.match_index[message['from_id']] = self.next_index[message['from_id']] - 1
                self.next_index[message['from_id']] = len(self.log)
                
                # Update commit index if possible
                for n in range(self.commit_index + 1, len(self.log)):
                    if self.log[n].term == self.current_term:
                        matched = 1  # Count self
                        for match_idx in self.match_index.values():
                            if match_idx >= n:
                                matched += 1
                        if matched > len(self.config['replicas']) // 2:
                            self.commit_index = n
            else:
                self.next_index[message['from_id']] = max(0, self.next_index[message['from_id']] - 1)

    def append_entry(self, command: bytes, timeout: float = 5.0) -> bool:
        """Append a new entry to the log (called by clients)"""
        with self.state_lock:
            if self.state != NodeState.LEADER:
                return False
            
            entry = LogEntry(
                term=self.current_term,
                command=command,
                index=len(self.log)
            )
            self.log.append(entry)
            self.save_persistent_state()
            
            # Wait for replication
            start_time = time.time()
            while time.time() - start_time < timeout:
                # Check if entry is committed
                if self.commit_index >= entry.index:
                    return True
                time.sleep(0.1)
            
            # If timeout, revert the entry
            self.log.pop()
            self.save_persistent_state()
            return False

    def get_committed_entries(self) -> List[bytes]:
        """Get all committed log entries"""
        return [entry.command for entry in self.log[:self.commit_index + 1]]
