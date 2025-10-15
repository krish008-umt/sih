import os
import spektral
print(spektral.__version__)
from tensorflow.keras.layers import Bidirectional
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
import re
import numpy as np
import tensorflow as tf
from spektral.layers import GCNConv, GlobalSumPool, GlobalAvgPool
from keras.layers import LayerNormalization

from tensorflow.keras.layers import LSTM, Dense, Input, Embedding, GlobalAveragePooling1D, GlobalMaxPooling1D, Concatenate, Dropout, Conv1D, MultiHeadAttention
from tensorflow.keras.models import Model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

# =============================
# MODIFIED: ENHANCED CONTEXT-AWARE LAYERS
# =============================
class RemoveMaskLayer(tf.keras.layers.Layer):
    def call(self, inputs, mask=None):
        return inputs
    def compute_mask(self, inputs, mask=None):
        return None

class CastToFloat(tf.keras.layers.Layer):
    def call(self, inputs, mask=None):
        return tf.cast(inputs, tf.float32)
    def compute_mask(self, inputs, mask=None):
        return None

class ProtocolStateDetector(tf.keras.layers.Layer):
    """NEW: Protocol state sequence detection using attention"""
    def __init__(self, units=64):
        super().__init__()
        self.units = units
        self.attention = MultiHeadAttention(num_heads=4, key_dim=units)
        self.state_detector = Dense(8, activation='sigmoid')  # 8 protocol states
    
    def call(self, inputs):
        attended = self.attention(inputs, inputs)
        state_probs = self.state_detector(attended)
        return state_probs

DATASET_PATH = r"C:\Users\Uday Sharma\Documents\SIH\PS 2\asm_all"
MAX_SEQ_LEN = 200
EMBED_DIM = 128
NODE_FEATURES = 45  # MODIFIED: Increased for advanced features
EPOCHS = 50
BATCH_SIZE = 16

# =============================
# MODIFIED: ENHANCED CONTEXT PATTERNS DATABASE
# =============================
CRYPTO_CONTEXT_PATTERNS = {
    'PASSWORD_HASHING': ['password', 'pwd', 'login', 'auth', 'verify', 'check_pass', 'credential'],
    'DIGITAL_SIGNATURE': ['sign', 'verify', 'certificate', 'signature', 'rsa_verify', 'ecdsa', 'dsa'],
    'NETWORK_SECURITY': ['ssl', 'tls', 'handshake', 'encrypt', 'decrypt', 'packet', 'socket', 'https'],
    'DATA_STORAGE': ['file', 'storage', 'save', 'write', 'read', 'config', 'database', 'flash'],
    'KEY_MANAGEMENT': ['key', 'generate', 'exchange', 'derive', 'session', 'key_schedule', 'keygen'],
    'RANDOM_GENERATION': ['random', 'rand', 'entropy', 'seed', 'prng', 'drbg', 'urandom'],
    'PROTOCOL_STATES': ['hello', 'handshake', 'exchange', 'finished', 'alert', 'change_cipher', 'nonce'],
    'BLOCKCHAIN': ['nonce', 'mining', 'block', 'transaction', 'hash', 'merkle', 'proofofwork'],
    'HARDWARE_CRYPTO': ['aesni', 'sha', 'accelerator', 'crypto', 'hardware', 'secure_element']
}

# NEW: Enhanced protocol state sequences with weights
PROTOCOL_STATE_SEQUENCES = {
    'TLS_HANDSHAKE': {
        'states': ['client_hello', 'server_hello', 'certificate', 'key_exchange', 'finished'],
        'weights': [0.9, 0.8, 0.7, 0.85, 0.75]
    },
    'SSH_AUTH': {
        'states': ['version_exchange', 'key_exchange', 'authentication', 'channel_open'],
        'weights': [0.8, 0.9, 0.85, 0.7]
    },
    'VPN_SETUP': {
        'states': ['init', 'handshake', 'tunnel_setup', 'data_transfer'],
        'weights': [0.7, 0.8, 0.75, 0.8]
    }
}

# NEW: Cryptographic constants for better detection
CRYPTO_CONSTANTS = {
    'AES_SBOX': ['63', '7c', '77', '7b', 'f2', '6b', '6f', 'c5'],
    'SHA256_INIT': ['6a09e667', 'bb67ae85', '3c6ef372', 'a54ff53a'],
    'MD5_INIT': ['67452301', 'efcdab89', '98badcfe', '10325476'],
    'DES_IP': ['00000000', 'ffffffff', '01234567', '89abcdef']
}

class AdvancedSemanticEmbedding(tf.keras.layers.Layer):
    def __init__(self, vocab_size, embed_dim, mask_zero=False):
        super().__init__()
        self.vocab_size = vocab_size
        self.embed_dim = embed_dim
        self.mask_zero = mask_zero
        
        self.embed = Embedding(input_dim=vocab_size, output_dim=embed_dim, mask_zero=False)
        self.semantic_encoder = Dense(embed_dim, activation='relu')
        self.position_embedding = tf.keras.layers.Embedding(input_dim=MAX_SEQ_LEN, output_dim=embed_dim)
        
    def build(self, input_shape):
        self.semantic_lookup = tf.keras.initializers.GlorotUniform()(shape=(self.vocab_size, 16))
        
    def call(self, inputs):
        if not inputs.dtype.is_integer:
            inputs = tf.cast(inputs, tf.int32)

        x = self.embed(inputs)
        
        positions = tf.range(start=0, limit=tf.shape(inputs)[1], delta=1)
        positions = tf.expand_dims(positions, 0)
        positions = tf.tile(positions, [tf.shape(inputs)[0], 1])
        pos_encoding = self.position_embedding(positions)
        
        semantic_features = tf.nn.embedding_lookup(self.semantic_lookup, inputs)
        semantic_features = self.semantic_encoder(semantic_features)
        
        x = x + semantic_features + pos_encoding
        return x

# =============================
# MODIFIED: ADVANCED CONTEXT-AWARE FEATURE EXTRACTION
# =============================
def extract_advanced_context_features(lines):
    """ENHANCED: More sophisticated context and protocol analysis"""
    opcodes = []
    context_scores = {key: 0.0 for key in CRYPTO_CONTEXT_PATTERNS.keys()}
    protocol_scores = {proto: 0.0 for proto in PROTOCOL_STATE_SEQUENCES.keys()}
    crypto_constants_found = {const: 0 for const in CRYPTO_CONSTANTS.keys()}
    addresses = []
    function_calls = []
    control_flow_sequence = []
    
    inside_code_section = False
    current_function = "main"
    current_address = None
    
    crypto_instructions = ['AES', 'SHA', 'RSA', 'DES', 'RC4', 'MD5', 'XOR', 'SBOX', 'ROUND', 'KEY']
    advanced_crypto_ops = ['AESENC', 'AESDEC', 'SHA256RND', 'PCLMUL', 'VPCLMUL']
    
    # NEW: Control flow analysis variables
    loop_depth = 0
    branch_count = 0
    crypto_operation_count = 0
    
    for line_num, line in enumerate(lines):
        line = line.strip()
        
        if not line or line.startswith(';') or line.startswith('#'):
            continue
            
        line = re.split(r'[;#]', line)[0].strip()
        if not line:
            continue
        
        # ENHANCED: Address extraction with function mapping
        address_match = re.match(r'^([0-9a-fA-F]+):', line)
        if address_match:
            current_address = address_match.group(1)
            addresses.append(current_address)
        
        # ENHANCED: Function call detection with context
        call_match = re.search(r'\b(call|bl|jmp)\s+([a-zA-Z_][a-zA-Z0-9_@]+)', line, re.IGNORECASE)
        if call_match:
            func_name = call_match.group(2)
            function_calls.append(func_name)
            control_flow_sequence.append(f"CALL_{func_name}")
        
        # ENHANCED: Cryptographic constant detection
        for const_name, const_values in CRYPTO_CONSTANTS.items():
            for const_val in const_values:
                if const_val in line.lower():
                    crypto_constants_found[const_name] += 1
        
        # ENHANCED: Context pattern matching with weights
        line_lower = line.lower()
        for context_type, patterns in CRYPTO_CONTEXT_PATTERNS.items():
            for pattern in patterns:
                if pattern in line_lower:
                    # Weight by position and frequency
                    weight = 1.0 + (line_num / len(lines)) * 0.5  # Later lines might be more significant
                    context_scores[context_type] += weight
        
        # ENHANCED: Protocol state detection with sequence awareness
        for protocol, proto_info in PROTOCOL_STATE_SEQUENCES.items():
            states = proto_info['states']
            weights = proto_info['weights']
            for i, state in enumerate(states):
                if state in line_lower:
                    protocol_scores[protocol] += weights[i]
        
        # NEW: Control flow analysis
        if any(branch in line.upper() for branch in ['JMP', 'JE', 'JNE', 'JZ', 'JNZ', 'CALL', 'RET']):
            branch_count += 1
            control_flow_sequence.append("BRANCH")
        
        if any(loop in line.upper() for loop in ['LOOP', 'REP']):
            loop_depth += 1
            control_flow_sequence.append("LOOP_START")
        
        if 'RET' in line.upper():
            if loop_depth > 0:
                loop_depth -= 1
                control_flow_sequence.append("LOOP_END")
            
        if re.match(r'^(?:section|segment)?\s*\.?text\b', line, re.IGNORECASE):
            inside_code_section = True
            continue
        elif re.match(r'^(?:section|segment)?\s*\.(?:data|bss|rdata|rodata)\b', line, re.IGNORECASE):
            inside_code_section = False
            continue
            
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*:', line) or re.match(r'^[0-9a-fA-F]+\s+<[^>]+>:', line):
            func_match = re.search(r'<([^>]+)>', line) if '<' in line else None
            if func_match:
                current_function = func_match.group(1)
            else:
                current_function = line.split(':')[0].strip()
            opcodes.append(f"FUNC_{current_function}")
            control_flow_sequence.append(f"FUNC_{current_function}")
            continue
    
        directives = ['db', 'dw', 'dd', 'dq', 'resb', 'resw', 'resd', 'resq', 
                     'times', 'equ', 'global', 'extern', 'end', 'align']
        
        first_word = line.split()[0].lower() if line.split() else ''
        if (not inside_code_section or 
            first_word in directives or
            line.startswith('.') or
            re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\s+equ', line, re.IGNORECASE)):
            continue
            
        parts = line.split()
        if len(parts) > 0:
            opcode = parts[0].upper()
            
            # NEW: Advanced crypto operation detection
            if opcode in advanced_crypto_ops:
                crypto_operation_count += 1
                full_instruction = opcode + "_ADV_CRYPTO"
                opcodes.append(full_instruction)
                control_flow_sequence.append("CRYPTO_OP")
                continue
            
            if (re.match(r'^[A-Z][A-Z0-9_]*$', opcode) and 
                len(opcode) >= 2 and
                opcode not in directives):
                
                full_instruction = opcode
                
                if len(parts) > 1:
                    operands = ' '.join(parts[1:]).upper()
                    
                    if any(crypto_op in opcode for crypto_op in crypto_instructions):
                        crypto_operation_count += 1
                        full_instruction = opcode + "_CRYPTO"
                        control_flow_sequence.append("CRYPTO_OP")
                    
                    elif any(constant in operands for constant in crypto_constants_found):
                        full_instruction = opcode + "_CONST"
                    
                    elif 'XOR' in operands and opcode in ['MOV', 'LEA', 'CMP']:
                        full_instruction = opcode + "_XORREF"
                    
                    elif any(loop_op in operands for loop_op in ['LOOP', 'REP', 'REPE', 'REPNE']):
                        full_instruction = opcode + "_LOOP"
                    
                    # NEW: Memory pattern analysis
                    elif any(mem_pattern in operands for mem_pattern in ['[BP', '[SP', 'PTR']):
                        full_instruction = opcode + "_MEM"
                
                opcodes.append(full_instruction)
                control_flow_sequence.append(opcode)
    
    # ENHANCED: Normalize and compute advanced metrics
    total_patterns = max(1, sum(context_scores.values()))
    for key in context_scores:
        context_scores[key] = min(1.0, context_scores[key] / total_patterns * 2)  # Scale to 0-1
    
    # Compute control flow complexity
    control_flow_complexity = len(set(control_flow_sequence)) / max(1, len(control_flow_sequence))
    branch_density = branch_count / max(1, len(opcodes))
    
    advanced_metrics = {
        'crypto_operation_count': crypto_operation_count,
        'control_flow_complexity': control_flow_complexity,
        'branch_density': branch_density,
        'loop_depth': loop_depth,
        'unique_functions': len(set(function_calls)),
        'crypto_constants': crypto_constants_found
    }
    
    return opcodes, context_scores, protocol_scores, addresses, function_calls, control_flow_sequence, advanced_metrics

# =============================
# MODIFIED: ADVANCED HYPERGRAPH WITH PROTOCOL AWARENESS
# =============================
def create_advanced_hypergraph(opcode_sequence, context_scores, protocol_scores, control_flow_seq, advanced_metrics, max_nodes=35):
    """ENHANCED: Advanced hypergraph with protocol and behavioral features"""
    seq_len = len(opcode_sequence)
    if seq_len == 0:
        return np.random.rand(1, NODE_FEATURES), np.eye(1)
    
    # Enhanced operation categories
    ARITHMETIC_OPS = ['ADD', 'SUB', 'MUL', 'DIV', 'INC', 'DEC', 'ADC', 'SBB', 'NEG']
    LOGICAL_OPS = ['AND', 'OR', 'XOR', 'NOT', 'TEST']
    SHIFT_OPS = ['SHL', 'SHR', 'ROL', 'ROR', 'SAL', 'SAR', 'RCL', 'RCR']
    MEMORY_OPS = ['MOV', 'LOAD', 'STORE', 'PUSH', 'POP', 'LEA', 'LDR', 'STR', 'LODS', 'STOS']
    CONTROL_OPS = ['CALL', 'RET', 'JMP', 'JE', 'JNE', 'JL', 'JG', 'LOOP', 'CMP', 'JZ', 'JNZ']
    CRYPTO_OPS = ['AES', 'SHA', 'RSA', 'DES', 'RC4', 'MD5', 'XOR', 'SBOX', 'ROUND', 'KEY']
    ADV_CRYPTO_OPS = ['AESENC', 'AESDEC', 'SHA256RND', 'PCLMUL', 'VPCLMUL']
    
    block_size = max(4, seq_len // max_nodes)
    num_nodes = min(seq_len // block_size, max_nodes)
    
    node_features = []
    opcode_counter = Counter(opcode_sequence)
    total_ops = len(opcode_sequence)
    
    reverse_vocab = {v: k for k, v in opcode_vocab.items()}
    
    for i in range(num_nodes):
        start_idx = i * block_size
        end_idx = min((i + 1) * block_size, seq_len)
        block = opcode_sequence[start_idx:end_idx]
        
        if len(block) == 0:
            features = [0] * NODE_FEATURES
            node_features.append(features)
            continue
            
        block_counter = Counter(block)
        block_ops = [reverse_vocab.get(op, 'UNK') for op in block]
        block_counter_str = Counter(block_ops)
        
        # ENHANCED: Advanced feature set
        features = [
            # Basic block features
            len(block), 
            len(set(block)) / len(block) if block else 0,
            
            # Operation type frequencies
            sum(block_counter_str.get(op, 0) for op in ARITHMETIC_OPS) / len(block),
            sum(block_counter_str.get(op, 0) for op in LOGICAL_OPS) / len(block),
            sum(block_counter_str.get(op, 0) for op in SHIFT_OPS) / len(block),
            sum(block_counter_str.get(op, 0) for op in MEMORY_OPS) / len(block),
            sum(block_counter_str.get(op, 0) for op in CONTROL_OPS) / len(block),
            
            # Crypto-specific features
            sum(block_counter_str.get(op, 0) for op in CRYPTO_OPS) / len(block),
            sum(block_counter_str.get(op, 0) for op in ADV_CRYPTO_OPS) / len(block),
            block_counter_str.get('XOR', 0) / len(block),
            block_counter_str.get('XOR_CRYPTO', 0) / len(block),
            
            # Information theory features
            -sum((count/len(block)) * np.log2(count/len(block)) 
                 for count in block_counter.values() if count > 0) if len(block) > 0 else 0,
            sum(1 for op in block if opcode_counter[op] / total_ops < 0.01) / len(block) if total_ops > 0 else 0,
            
            # Advanced crypto patterns
            max(block_counter.values()) / len(block) if block else 0,
            len([op for op in block_ops if 'CRYPTO' in op]) / len(block),
            len([op for op in block_ops if 'LOOP' in op]) / len(block),
            len([op for op in block_ops if 'FUNC_' in op]) / len(block),
            len([op for op in block_ops if any(crypto in op for crypto in ['AES', 'SHA', 'RSA'])]) / len(block),
            
            # Context-aware features
            context_scores.get('PASSWORD_HASHING', 0),
            context_scores.get('DIGITAL_SIGNATURE', 0),
            context_scores.get('NETWORK_SECURITY', 0),
            context_scores.get('DATA_STORAGE', 0),
            context_scores.get('KEY_MANAGEMENT', 0),
            context_scores.get('RANDOM_GENERATION', 0),
            context_scores.get('PROTOCOL_STATES', 0),
            
            # Protocol features
            protocol_scores.get('TLS_HANDSHAKE', 0),
            protocol_scores.get('SSH_AUTH', 0),
            protocol_scores.get('VPN_SETUP', 0),
            
            # Behavioral patterns
            len([op for op in block_ops if 'CALL' in op]) / len(block),
            len([op for op in block_ops if 'RET' in op]) / len(block),
            len([op for op in block_ops if 'CMP' in op]) / len(block),
            
            # NEW: Advanced metrics
            advanced_metrics['control_flow_complexity'],
            advanced_metrics['branch_density'],
            advanced_metrics['loop_depth'] / 10.0,  # Normalized
            advanced_metrics['crypto_operation_count'] / max(1, len(opcode_sequence)),
            
            # NEW: Crypto constant indicators
            sum(advanced_metrics['crypto_constants'].values()) / 10.0,
            
            # NEW: Memory access patterns
            len([op for op in block_ops if '_MEM' in op]) / len(block),
            
            # NEW: Function call density
            advanced_metrics['unique_functions'] / max(1, len(opcode_sequence)),
        ]
        
        # Pad features if needed
        while len(features) < NODE_FEATURES:
            features.append(0)
        node_features.append(features[:NODE_FEATURES])
    
    # ENHANCED: Advanced hypergraph construction
    num_nodes = len(node_features)
    if num_nodes == 0:
        return np.random.rand(1, NODE_FEATURES), np.eye(1)
    
    num_hyperedges = min(15, num_nodes)
    H = np.zeros((num_nodes, num_hyperedges))
    
    for i in range(num_nodes):
        # Basic sequential connectivity
        if i < num_nodes - 1:
            H[i, i % num_hyperedges] = 1
            H[i+1, i % num_hyperedges] = 1
        
        # Crypto-aware connectivity
        if i < num_nodes - 2:
            crypto_score = (node_features[i][6] + node_features[i][7] + 
                          node_features[i][8] + node_features[i][12])
            if crypto_score > 0.1:  
                H[i, (i+2) % num_hyperedges] = 1
                H[i+1, (i+2) % num_hyperedges] = 1
                H[i+2, (i+2) % num_hyperedges] = 1
        
        # Protocol-aware connectivity
        if i < num_nodes - 3:
            protocol_score = (node_features[i][24] + node_features[i][25] + 
                            node_features[i][26])
            if protocol_score > 0.15:
                for j in range(4):
                    if i + j < num_nodes:
                        H[i+j, (i+3) % num_hyperedges] = 1
    
    A = H @ H.T
    np.fill_diagonal(A, 1)
    A = np.tanh(A * 1.5)  # Enhanced scaling
    
    return np.array(node_features), A

# =============================
# MODIFIED: ENHANCED MAIN PROCESSING LOOP
# =============================
opcode_vocab = {}
opcode_index = 1
X_seq, X_graph_nodes, X_graph_adj, Y = [], [], [], []
X_context = []
file_contexts = []

print("[INFO] Reading .asm dataset with ADVANCED context-aware crypto detection...")

for label_idx, algo_folder in enumerate(os.listdir(DATASET_PATH)):
    algo_path = os.path.join(DATASET_PATH, algo_folder)
    if not os.path.isdir(algo_path):
        continue
    
    print(f" Processing {algo_folder}...")
    files_processed = 0
    
    for root, dirs, files in os.walk(algo_path):
        for file in files:
            if not (file.lower().endswith('.asm') or file.lower().endswith('.txt')):
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()

                # ENHANCED: Advanced feature extraction
                seq_tokens, context_scores, protocol_scores, addresses, function_calls, control_flow_seq, advanced_metrics = extract_advanced_context_features(lines)

                if len(seq_tokens) < 10: 
                    print(f"   {file}: skipped ({len(seq_tokens)} tokens)")
                    continue

                # Sequence processing
                seq = []
                for token in seq_tokens:
                    if token not in opcode_vocab:
                        opcode_vocab[token] = opcode_index
                        opcode_index += 1
                    seq.append(opcode_vocab[token])

                X_seq.append(seq)
                Y.append(label_idx)
                
                # ENHANCED: Advanced hypergraph
                Xn, A = create_advanced_hypergraph(seq_tokens, context_scores, protocol_scores, control_flow_seq, advanced_metrics)
                X_graph_nodes.append(Xn)
                X_graph_adj.append(A)
                
                # Store context features
                context_features = list(context_scores.values()) + list(protocol_scores.values())
                X_context.append(context_features)
                
                # Enhanced context info
                file_contexts.append({
                    'file': file,
                    'algorithm': algo_folder,
                    'addresses': addresses,
                    'function_calls': function_calls,
                    'context_scores': context_scores,
                    'protocol_scores': protocol_scores,
                    'control_flow_seq': control_flow_seq[:20],  # First 20 elements
                    'advanced_metrics': advanced_metrics
                })

                files_processed += 1
                print(f"   {file}: {len(seq)} opcodes, {len(addresses)} addrs, {advanced_metrics['crypto_operation_count']} crypto ops")

            except Exception as e:
                print(f"   Error processing {file}: {e}")
                continue

print(f"\n[INFO] Enhanced Dataset Summary:")
print(f" Total samples: {len(X_seq)}")
print(f" Vocabulary size: {len(opcode_vocab)}")
print(f" Context features: {len(X_context[0]) if X_context else 0}")
print(f" Class distribution: {Counter(Y)}")

# =============================
# DATA PREPARATION AND SPLITTING
# =============================
print("\n[INFO] Preparing data for training...")

# class_names definition
class_names = [f"Class_{i}" for i in range(len(set(Y)))]

# Remap labels to sequential range
unique_labels = sorted(list(set(Y)))
label_map = {old_label: new_label for new_label, old_label in enumerate(unique_labels)}
Y_mapped = [label_map[label] for label in Y]
Y = np.array(Y_mapped)

print(f" Remapped Class distribution: {Counter(Y)}")
print(f" Number of unique classes: {len(set(Y))}")

if len(X_seq) == 0:
    print(" ERROR: No data processed! Check your .asm files and dataset path.")
    exit()

# Pad sequences
X_seq = pad_sequences(X_seq, maxlen=MAX_SEQ_LEN, padding='post', truncating='post')

# Train-test split
n_samples = len(Y)
test_size = min(0.2, max(0.1, 20/len(Y)))  # Ensure at least 10% test size
train_idx, test_idx = train_test_split(np.arange(n_samples), test_size=test_size, stratify=Y, random_state=42)

X_seq_train, X_seq_test = X_seq[train_idx], X_seq[test_idx]
Y_train, Y_test = Y[train_idx], Y[test_idx]

X_graph_train = [X_graph_nodes[i] for i in train_idx]
A_graph_train = [X_graph_adj[i] for i in train_idx]
X_graph_test = [X_graph_nodes[i] for i in test_idx]
A_graph_test = [X_graph_adj[i] for i in test_idx]

# Padding graphs
max_nodes = max([A.shape[0] for A in X_graph_adj]) if X_graph_adj else 1
print(f"[INFO] Maximum nodes in graphs: {max_nodes}")

def pad_graph(X, A, max_nodes):
    pad_x = np.zeros((max_nodes, NODE_FEATURES))
    pad_x[:X.shape[0], :] = X
    pad_a = np.zeros((max_nodes, max_nodes))
    pad_a[:A.shape[0], :A.shape[1]] = A
    return pad_x, pad_a

Xn_train_padded, An_train_padded = [], []
for i in range(len(X_graph_train)):
    xg, ag = pad_graph(X_graph_train[i], A_graph_train[i], max_nodes)
    Xn_train_padded.append(xg)
    An_train_padded.append(ag)
Xn_train_padded = np.array(Xn_train_padded)
An_train_padded = np.array(An_train_padded)

Xn_test_padded, An_test_padded = [], []
for i in range(len(X_graph_test)):
    xg, ag = pad_graph(X_graph_test[i], A_graph_test[i], max_nodes)
    Xn_test_padded.append(xg)
    An_test_padded.append(ag)
Xn_test_padded = np.array(Xn_test_padded)
An_test_padded = np.array(An_test_padded)

print(f"[INFO] Final training shapes:")
print(f"  Sequences: {X_seq_train.shape}")
print(f"  Graph nodes: {Xn_train_padded.shape}")
print(f"  Graph adjacency: {An_train_padded.shape}")

# =============================
# PREPARE MULTI-TASK LABELS
# =============================
print("[INFO] Preparing multi-task labels...")

Y_context = []
Y_protocol = []

for file_ctx in file_contexts:
    # Context labels (multi-label)
    context_labels = [1 if score > 0.1 else 0 for score in file_ctx['context_scores'].values()]
    Y_context.append(context_labels[:8])  # First 8 context types
    
    # Protocol labels (multi-label)  
    protocol_labels = [1 if score > 0.1 else 0 for score in file_ctx['protocol_scores'].values()]
    Y_protocol.append(protocol_labels[:3])  # First 3 protocol types

Y_context = np.array(Y_context)
Y_protocol = np.array(Y_protocol)

# Split for multi-task
Y_context_train, Y_context_test = Y_context[train_idx], Y_context[test_idx]
Y_protocol_train, Y_protocol_test = Y_protocol[train_idx], Y_protocol[test_idx]


print("\n[INFO] Building Advanced Multi-Modal Crypto Detection Model...")

# ENHANCED: Multi-head attention for protocol states
seq_input = Input(shape=(MAX_SEQ_LEN,), name="seq_input", dtype='int32')
node_features_in = Input(shape=(max_nodes, NODE_FEATURES), name="node_features")
adj_in = Input(shape=(max_nodes, max_nodes), name="adjacency")

masked_node_features = tf.keras.layers.Masking(mask_value=0.0)(node_features_in)
node_features_cast = CastToFloat()(masked_node_features)
mask_nodes = tf.keras.layers.Lambda(
    lambda x: tf.expand_dims(tf.cast(tf.reduce_any(tf.not_equal(x, 0), axis=-1), tf.float32), -1)
)(masked_node_features)

# ENHANCED LSTM with attention
print("[INFO] Building enhanced LSTM with attention...")
x = AdvancedSemanticEmbedding(len(opcode_vocab)+1, EMBED_DIM, mask_zero=False)(seq_input)

# Multi-scale LSTM
lstm1 = Bidirectional(
    LSTM(64, return_sequences=True, dropout=0.3, recurrent_dropout=0.2), 
    name='bilstm_1'
)(x)
lstm1_att = MultiHeadAttention(num_heads=4, key_dim=64)(lstm1, lstm1)
lstm1_norm = LayerNormalization()(lstm1_att)

# Layer 2: Bidirectional for pattern recognition  
lstm2 = Bidirectional(
    LSTM(64, return_sequences=True, dropout=0.3, recurrent_dropout=0.2),
    name='bilstm_2'
)(lstm1_norm)
lstm2_att = MultiHeadAttention(num_heads=4, key_dim=64)(lstm2, lstm2)
lstm2_norm = LayerNormalization()(lstm2_att)

# Layer 3: Final compression (unidirectional)
lstm3 = LSTM(64, return_sequences=False, dropout=0.2, name='lstm_final')(lstm2_norm)
lstm_output = LayerNormalization()(lstm3)

# Enhanced CNN with multiple kernel sizes
print("[INFO] Building multi-scale CNN...")
embedding = AdvancedSemanticEmbedding(len(opcode_vocab)+1, EMBED_DIM)(seq_input)
conv1 = Conv1D(64, 3, activation='relu', padding='same')(embedding)
conv2 = Conv1D(64, 5, activation='relu', padding='same')(embedding)
conv3 = Conv1D(64, 7, activation='relu', padding='same')(embedding)
conv_merged = Concatenate()([conv1, conv2, conv3])
conv_pool = GlobalMaxPooling1D()(conv_merged)

# ENHANCED GNN with residual connections
print("[INFO] Building enhanced GNN with residuals...")
g = GCNConv(128, activation='relu', name='gnn_1')([node_features_cast, adj_in], mask=[mask_nodes, None])
g_res1 = g
g = LayerNormalization()(g)
g = Dropout(0.3)(g)

g = GCNConv(128, activation='relu', name='gnn_2')([g, adj_in], mask=[mask_nodes, None])
g = tf.keras.layers.Add()([g, g_res1])  # Residual connection
g = LayerNormalization()(g)
g = Dropout(0.3)(g)

g = GCNConv(64, activation='relu', name='gnn_3')([g, adj_in], mask=[mask_nodes, None])
g = LayerNormalization()(g)
g = Dropout(0.2)(g)

g_max = GlobalSumPool()(g)
g_avg = GlobalAvgPool()(g)
gnn_output = Concatenate()([g_max, g_avg])

# NEW: Protocol State Detection Branch
print("[INFO] Building protocol state detector...")
protocol_features = tf.keras.layers.Dense(64, activation='relu')(lstm2_norm)
protocol_states = ProtocolStateDetector()(protocol_features)
protocol_pool = GlobalMaxPooling1D()(protocol_states)

# Enhanced fusion
print("[INFO] Building advanced fusion mechanism...")
merged = Concatenate()([lstm_output, conv_pool, gnn_output, protocol_pool])
merged_clean = RemoveMaskLayer()(merged)

# Enhanced classification with multiple heads
print("[INFO] Building multi-task classification head...")

# Main algorithm classification
x = Dense(256, activation='relu')(merged_clean)
x = LayerNormalization()(x)
x = Dropout(0.4)(x)
x = Dense(128, activation='relu')(x)
x = LayerNormalization()(x)
x = Dropout(0.3)(x)

# Multi-output for enhanced analysis
algorithm_output = Dense(len(set(Y)), activation='softmax', name='algorithm_classification')(x)
context_output = Dense(8, activation='sigmoid', name='context_prediction')(x)  # 8 context types
protocol_output = Dense(3, activation='sigmoid', name='protocol_prediction')(x)  # 3 protocol types

# Create multi-output model
model = Model(
    inputs=[seq_input, node_features_in, adj_in], 
    outputs=[algorithm_output, context_output, protocol_output]
)

# =============================
# MODEL COMPILATION AND TRAINING
# =============================
print("[INFO] Setting up multi-task training...")

# Callbacks
callbacks_list = [
    tf.keras.callbacks.EarlyStopping(monitor='val_algorithm_classification_accuracy', patience=15, restore_best_weights=True, mode='max'),
    tf.keras.callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=8, min_lr=1e-7),
    tf.keras.callbacks.ModelCheckpoint('best_crypto_model.keras', monitor='val_algorithm_classification_accuracy', save_best_only=True, mode='max')
]
model.compile(
    optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
    loss={
        'algorithm_classification': 'sparse_categorical_crossentropy',
        'context_prediction': 'binary_crossentropy',
        'protocol_prediction': 'binary_crossentropy'
    },
    loss_weights={
        'algorithm_classification': 1.0,
        'context_prediction': 0.3,
        'protocol_prediction': 0.3
    },
    metrics={
        'algorithm_classification': ['accuracy', 'sparse_categorical_accuracy'],
        'context_prediction': ['accuracy'],
        'protocol_prediction': ['accuracy']
    }
)

model.summary()

print("[INFO] Training Advanced Multi-Task Crypto Detection Model...")
history = model.fit(
    [X_seq_train, Xn_train_padded, An_train_padded],
    {
        'algorithm_classification': Y_train,
        'context_prediction': Y_context_train,
        'protocol_prediction': Y_protocol_train
    },
    validation_data=(
        [X_seq_test, Xn_test_padded, An_test_padded],
        {
            'algorithm_classification': Y_test,
            'context_prediction': Y_context_test, 
            'protocol_prediction': Y_protocol_test
        }
    ),
    epochs=EPOCHS,
    batch_size=BATCH_SIZE,
    callbacks=callbacks_list,
    verbose=1,
    shuffle=True
)

# =============================
# MODEL EVALUATION
# =============================
print("\n[INFO] Performing comprehensive multi-task evaluation...")

# Evaluate all outputs
eval_results = model.evaluate(
    [X_seq_test, Xn_test_padded, An_test_padded],
    {
        'algorithm_classification': Y_test,
        'context_prediction': Y_context_test,
        'protocol_prediction': Y_protocol_test
    },
    verbose=0
)

# Enhanced classification report
y_pred = model.predict([X_seq_test, Xn_test_padded, An_test_padded], verbose=0)
y_pred_classes = np.argmax(y_pred[0], axis=1)

print(f"\n COMPREHENSIVE RESULTS:")
print(f" Algorithm Accuracy: {eval_results[4]:.4f}")
print(f" Context Prediction Accuracy: {eval_results[5]:.4f}")
print(f" Protocol Prediction Accuracy: {eval_results[6]:.4f}")
print(f" Total Loss: {eval_results[0]:.4f}")

print("\n DETAILED ALGORITHM CLASSIFICATION REPORT:")
print(classification_report(Y_test, y_pred_classes, target_names=class_names))

# Save enhanced model
model.save("advanced_crypto_analyzer_final.keras")
print("\n Advanced model saved successfully!")

# =============================
# ENHANCED VISUALIZATION SECTION
# =============================
print("\n[INFO] Generating Advanced Visualizations...")

plt.figure(figsize=(15, 12))

# 1. CONFUSION MATRIX
plt.subplot(2, 3, 1)
cm = confusion_matrix(Y_test, y_pred_classes)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=class_names, yticklabels=class_names)
plt.title('Confusion Matrix\n(Algorithm Classification)', fontsize=14, fontweight='bold')
plt.xlabel('Predicted Algorithm')
plt.ylabel('Actual Algorithm')
plt.xticks(rotation=45)
plt.yticks(rotation=0)

# 2. ACCURACY TRENDS
plt.subplot(2, 3, 2)
plt.plot(history.history['algorithm_classification_accuracy'], 
         'o-', label='Train Accuracy', linewidth=2, markersize=4, color='blue')
plt.plot(history.history['val_algorithm_classification_accuracy'], 
         's-', label='Validation Accuracy', linewidth=2, markersize=4, color='red')
plt.title('Algorithm Accuracy Over Time', fontsize=14, fontweight='bold')
plt.xlabel('Epoch')
plt.ylabel('Accuracy')
plt.legend()
plt.grid(True, alpha=0.3)
plt.ylim(0, 1)

# 3. CONTEXT & PROTOCOL ACCURACY
plt.subplot(2, 3, 3)
context_accuracy = history.history.get('val_context_prediction_accuracy', [0.5] * len(history.history['val_algorithm_classification_accuracy']))
protocol_accuracy = history.history.get('val_protocol_prediction_accuracy', [0.5] * len(history.history['val_algorithm_classification_accuracy']))

plt.plot(context_accuracy, '^-', label='Context Accuracy', linewidth=2, markersize=4, color='green')
plt.plot(protocol_accuracy, 'd-', label='Protocol Accuracy', linewidth=2, markersize=4, color='orange')
plt.title('Context & Protocol Accuracy', fontsize=14, fontweight='bold')
plt.xlabel('Epoch')
plt.ylabel('Accuracy')
plt.legend()
plt.grid(True, alpha=0.3)
plt.ylim(0, 1)

# 4. LOSS TRENDS
plt.subplot(2, 3, 4)
plt.plot(history.history['loss'], 'o-', label='Total Loss', linewidth=2, markersize=4, color='purple')
plt.plot(history.history['algorithm_classification_loss'], 
         's-', label='Algorithm Loss', linewidth=2, markersize=4, color='red')
plt.title('Training Loss Over Time', fontsize=14, fontweight='bold')
plt.xlabel('Epoch')
plt.ylabel('Loss')
plt.legend()
plt.grid(True, alpha=0.3)

# 5. CLASS DISTRIBUTION
plt.subplot(2, 3, 5)
class_counts = Counter(Y)
plt.bar(range(len(class_counts)), class_counts.values(), 
        color=['skyblue', 'lightgreen', 'orange', 'pink', 'lightcoral'])
plt.title('Algorithm Class Distribution', fontsize=14, fontweight='bold')
plt.xlabel('Algorithm Class')
plt.ylabel('Number of Samples')
plt.xticks(range(len(class_counts)), class_names, rotation=45)
plt.grid(True, alpha=0.3)

# 6. CONFIDENCE DISTRIBUTION
plt.subplot(2, 3, 6)
confidences = np.max(y_pred[0], axis=1)
plt.hist(confidences, bins=20, color='lightblue', alpha=0.7, edgecolor='black')
plt.title('Prediction Confidence Distribution', fontsize=14, fontweight='bold')
plt.xlabel('Confidence Score')
plt.ylabel('Number of Predictions')
plt.grid(True, alpha=0.3)
plt.axvline(x=0.8, color='red', linestyle='--', label='High Confidence Threshold')
plt.legend()

plt.tight_layout()
plt.savefig('comprehensive_crypto_analysis_final.png', dpi=300, bbox_inches='tight')
plt.show()

# =============================
# DETAILED PERFORMANCE REPORT
# =============================
print("\n" + "="*70)
print("COMPREHENSIVE PERFORMANCE REPORT")
print("="*70)

# Algorithm Classification Metrics
algo_accuracy = eval_results[4]
context_accuracy = eval_results[5] if len(eval_results) > 5 else 0.0
protocol_accuracy = eval_results[6] if len(eval_results) > 6 else 0.0

print(f"\n ACCURACY SCORES:")
print(f"  Algorithm Classification: {algo_accuracy:.4f} ({algo_accuracy*100:.2f}%)")
print(f"  Context Prediction:       {context_accuracy:.4f} ({context_accuracy*100:.2f}%)")
print(f"  Protocol Detection:       {protocol_accuracy:.4f} ({protocol_accuracy*100:.2f}%)")

# Confidence Analysis
high_confidence = np.sum(confidences > 0.8) / len(confidences) * 100
medium_confidence = np.sum((confidences > 0.6) & (confidences <= 0.8)) / len(confidences) * 100
low_confidence = np.sum(confidences <= 0.6) / len(confidences) * 100

print(f"\n CONFIDENCE ANALYSIS:")
print(f"  High Confidence (>80%):   {high_confidence:.2f}%")
print(f"  Medium Confidence (60-80%): {medium_confidence:.2f}%")
print(f"  Low Confidence (<60%):    {low_confidence:.2f}%")

print(f"\n MODEL CAPABILITIES:")
print(f"  ✓ Multi-Algorithm Detection")
print(f"  ✓ Usage Context Analysis") 
print(f"  ✓ Protocol State Detection")
print(f"  ✓ Security Assessment")
print(f"  ✓ Behavioral Pattern Recognition")

print("="*70)

# =============================
# SAMPLE PREDICTION VISUALIZATION
# =============================
print("\n[INFO] Generating Sample Prediction Examples...")

# Show first 3 test samples with their predictions
for i in range(min(3, len(X_seq_test))):
    sample_idx = test_idx[i]
    actual_class = Y_test[i]
    predicted_class = y_pred_classes[i]
    confidence = confidences[i]
    
    print(f"\n🔍 Sample {i+1}:")
    print(f"   Actual: {class_names[actual_class]}")
    print(f"   Predicted: {class_names[predicted_class]}")
    print(f"   Confidence: {confidence:.4f}")
    print(f"   Correct: {'✓' if actual_class == predicted_class else '✗'}")
    
    # Show top 3 predictions
    top_3_indices = np.argsort(y_pred[0][i])[-3:][::-1]
    print(f"   Top Predictions:")
    for j, idx in enumerate(top_3_indices):
        prob = y_pred[0][i][idx]
        print(f"     {j+1}. {class_names[idx]}: {prob:.4f}")

print(" VISUALIZATION COMPLETED!")
print(" Charts saved as 'comprehensive_crypto_analysis.png'")
print(" MODEL TRAINING AND EVALUATION COMPLETED SUCCESSFULLY!")w