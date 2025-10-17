#!/usr/bin/env python
# encoding: utf-8
"""
Mutator used to generate GUI operations, including AT-SPI accessibility API based operations.  
"""

import random

def init(seed):
    """
    Called once when AFLFuzz starts up. Used to seed our RNG.

    @type seed: int
    @param seed: A 32-bit random value
    """
    random.seed(seed)

def deinit():
    pass

def fuzz(buf, add_buf, max_size):
    """
    Called per fuzzing iteration.

    @type buf: bytearray
    @param buf: The buffer that should be mutated.

    @type add_buf: bytearray
    @param add_buf: A second buffer that can be used as mutation source.

    @type max_size: int
    @param max_size: Maximum size of the mutated output. The mutation must not
        produce data larger than max_size.

    @rtype: bytearray
    @return: A new bytearray containing the mutated data
    """

    # Convert buffer to mutable bytearray
    buf = bytearray(buf)

    # Select a random (weighted) mutation
    mutation_func = random.choices([m[0] for m in mutations], weights=[m[1] for m in mutations], k=1)[0]

    return mutation_func(buf, add_buf, max_size)

"""
    Mutations:

    Insert 10 random operations to the core buffer
    Insert 50 random operations to the core buffer
    Modify 10 random operations in the core buffer
    Modify 50 random operations in the core buffer
    Remove 10 random operations
    Append the secondary buffer to the core buffer
    Prepend the secondary buffer to the core buffer
    Interleave the primary and secondary buffers
    Generate an entirely new buffer (with 50-100 operations)
    Generate an entirely new buffer (with 200-500 operations)
"""

def insert_10_random_operations(buf, add_buf, max_size):
    # Perform 10 random ops
    for _ in range(10):
        random.choice([f for f, w in ops for _ in range(w)])(buf, add_buf)

    # Ensure the buffer does not exceed max_size
    return buf[:max_size]

def insert_50_random_operations(buf, add_buf, max_size):
    # Insert 50 random ops
    for _ in range(50):
        random.choice([f for f, w in ops for _ in range(w)])(buf, add_buf)

    # Ensure the buffer does not exceed max_size
    return buf[:max_size]

def modify_10_random_operations(buf, add_buf, max_size):
    # Perform 10 random modifications
    for _ in range(10):
        modify_operation(buf)

    # Ensure the buffer does not exceed max_size
    return buf[:max_size]

def remove_10_random_operations(buf, add_buf, max_size):
    # Perform 10 random deletions
    for _ in range(10):
        remove_random_operation(buf)

    # Ensure the buffer does not exceed max_size
    return buf[:max_size]

def generate_new_buffer(buf, add_buf, max_size):
    """
    Generate a new buffer with 50–100 operations.
    """
    num_operations = random.randint(50, 100)
    buf = bytearray()
    
    for _ in range(num_operations):
        operation_type = random.choice([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2])  # 1 for click
        operation = bytearray([operation_type, random.getrandbits(8), random.getrandbits(8)])
        buf.extend(operation)

    # Ensure the buffer does not exceed max_size
    return buf[:max_size]

def generate_new_buffer_big(buf, add_buf, max_size):
    """
    Generate a new buffer with 200–500 operations.
    """
    num_operations = random.randint(200, 2000)
    buf = bytearray()
    
    for _ in range(num_operations):
        operation_type = random.choice([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2])  # 1 for click
        operation = bytearray([operation_type, random.getrandbits(8), random.getrandbits(8)])
        buf.extend(operation)

def append_add_buf_mutation(buf, add_buf, max_size):
    """
    Append the contents of add_buf to buf.
    """
    buf.extend(add_buf)
    return buf[:max_size]

def prepend_add_buf_mutation(buf, add_buf, max_size):
    """
    Prepend the contents of add_buf to buf.
    """
    buf[:0] = add_buf
    return buf[:max_size]

def interleave_buffers(buf, add_buf, max_size):
    """
    Interleave operations from the buffers
    """
    result = bytearray()
    i, j = 0, 0
    toggle = True  # True for buf1, False for buf2

    while len(result) < max_size and (i < len(buf) or j < len(add_buf)):
        if toggle:
            chunk = buf[i:i+3]
            i += 3
        else:
            chunk = add_buf[j:j+3]
            j += 3

        result.extend(chunk)
        toggle = not toggle

    return result[:max_size]


mutations = [(remove_10_random_operations, 10), (interleave_buffers, 10), (prepend_add_buf_mutation, 10), (append_add_buf_mutation, 10), (insert_10_random_operations, 10), (insert_50_random_operations, 10), (generate_new_buffer, 10), (generate_new_buffer_big, 10), (modify_10_random_operations, 10)]

"""
    Operations:

    1xx - Random Click at a Random Location
    2xx - Close current window
    3xx - Random keypress
    4xx - Click an entry element (also adds 5 random keypresses after) 
    5xx - Click a push button 
    6xx - Click a toggle button
    7xx - Click a check box
    8xx - Click a radio button
    9xx - Click a combo box
    10xx - Click a menu item
    11xx - Interact with a scroll bar
    12xx - Click a slider
    13xx - Click a spin button
    14xx - Click a table cell
"""

def add_random_click_operation(buf, add_buf):
    """
    Add a click operation represented by 3 bytes starting with 1.
    """
    operation = bytearray([1, random.getrandbits(8), random.getrandbits(8)])
    insert_at = random.randint(0, len(buf) // 3) * 3  # Insert only at valid boundaries
    buf[insert_at:insert_at] = operation
    
def add_atspi_entry_operation(buf, add_buf):
    """ 
    Add a click entry operation represented by 3 bytes starting with 4
    Then add 3 random keypresses after
    """
    operation = bytearray([4, random.getrandbits(8), random.getrandbits(8), 3, random.getrandbits(8), random.getrandbits(8), 3, random.getrandbits(8), random.getrandbits(8)])
    insert_at = random.randint(0, len(buf) // 3) * 3  # Insert only at valid boundaries
    buf[insert_at:insert_at] = operation

def add_atspi_push_button_operation(buf, add_buf):
    """ 
    Add a click entry operation represented by 3 bytes starting with 5
    Then add 3 random keypresses after
    """
    operation = bytearray([5, random.getrandbits(8), random.getrandbits(8)])
    insert_at = random.randint(0, len(buf) // 3) * 3  # Insert only at valid boundaries
    buf[insert_at:insert_at] = operation

def add_atspi_toggle_button_operation(buf, add_buf):
    """ 
    Add a click toggle button operation represented by 3 bytes starting with 6
    """
    operation = bytearray([6, random.getrandbits(8), random.getrandbits(8)])
    insert_at = random.randint(0, len(buf) // 3) * 3  # Insert only at valid boundaries
    buf[insert_at:insert_at] = operation

def add_atspi_check_box_operation(buf, add_buf):
    """ 
    Add a click check box operation represented by 3 bytes starting with 7
    """
    operation = bytearray([7, random.getrandbits(8), random.getrandbits(8)])
    insert_at = random.randint(0, len(buf) // 3) * 3  # Insert only at valid boundaries
    buf[insert_at:insert_at] = operation

def add_atspi_radio_button_operation(buf, add_buf):
    """ 
    Add a click radio button operation represented by 3 bytes starting with 8
    """
    operation = bytearray([8, random.getrandbits(8), random.getrandbits(8)])
    insert_at = random.randint(0, len(buf) // 3) * 3  # Insert only at valid boundaries
    buf[insert_at:insert_at] = operation

def add_atspi_combo_box_operation(buf, add_buf):
    """ 
    Add a click combo box operation represented by 3 bytes starting with 9
    """
    operation = bytearray([9, random.getrandbits(8), random.getrandbits(8)])
    insert_at = random.randint(0, len(buf) // 3) * 3  # Insert only at valid boundaries
    buf[insert_at:insert_at] = operation

def add_atspi_menu_item_operation(buf, add_buf):
    """ 
    Add a click menu item operation represented by 3 bytes starting with 10
    """
    operation = bytearray([10, random.getrandbits(8), random.getrandbits(8)])
    insert_at = random.randint(0, len(buf) // 3) * 3  # Insert only at valid boundaries
    buf[insert_at:insert_at] = operation

def add_atspi_table_cell_operation(buf, add_buf):
    """ 
    Add a click table cell operation represented by 3 bytes starting with 14
    """
    operation = bytearray([14, random.getrandbits(8), random.getrandbits(8)])
    insert_at = random.randint(0, len(buf) // 3) * 3  # Insert only at valid boundaries
    buf[insert_at:insert_at] = operation

def add_atspi_spin_button_operation(buf, add_buf):
    """ 
    Add a click spin button operation represented by 3 bytes starting with 13
    """
    operation = bytearray([13, random.getrandbits(8), random.getrandbits(8)])
    insert_at = random.randint(0, len(buf) // 3) * 3  # Insert only at valid boundaries
    buf[insert_at:insert_at] = operation

def add_lower_operation(buf, add_buf):
    """
    Add a lower operation represented by 3 bytes starting with 2.
    """
    operation = bytearray([2, random.getrandbits(8), random.getrandbits(8)])
    insert_at = random.randint(0, len(buf) // 3) * 3  # Insert only at valid boundaries
    buf[insert_at:insert_at] = operation


def modify_operation(buf):
    """
    Modify the second and third bytes of an existing operation.
    Assumes operations are 3 bytes long.
    """
    if len(buf) < 3:
        return  # No operations to modify

    # Find a random operation to modify
    operation_index = random.randint(0, (len(buf) // 3) - 1) * 3
    buf[operation_index + 1] = random.getrandbits(8)
    buf[operation_index + 2] = random.getrandbits(8)

def remove_random_operation(buf):
    """
    Remove a random operation from buf.
    Assumes operations are 3 bytes long.
    """
    if len(buf) < 3:
        return  # No operations to remove

    # Find a random operation to remove
    operation_index = random.randint(0, (len(buf) // 3) - 1) * 3
    del buf[operation_index : operation_index + 3]

ops = [(add_atspi_table_cell_operation, 5), (add_atspi_spin_button_operation, 5), (add_atspi_menu_item_operation, 5), (add_atspi_combo_box_operation, 5), (add_atspi_radio_button_operation, 5), (add_atspi_check_box_operation, 5), (add_random_click_operation, 20), (add_lower_operation, 3), (add_atspi_push_button_operation, 5), (add_atspi_toggle_button_operation, 5)]

"""
Trimming


The algorithm partitions the input into 'total steps' parts, where each part is the same number of operations. It then sequentially attempts to remove each part from the input. N can be configured to balance the time to complete trimming vs the amount of non-coverage increasing operations left behind.


"""
original_input = None
current_input = None
failed_removals = 0
total_steps = 4
current_step = 0

def init_trim(buf):
    """Initialize trimming by storing the original input and resetting state."""
    if len(buf) % 3 == 0:
        print("broken testcase")

    global original_input, current_input, failed_removals
    original_input = buf
    current_input = buf
    failed_removals = 0
    return min(total_steps, len(buf))

def trim():
    """Attempt to remove the next % chunk of input, skipping past failed removals."""
    global original_input, current_input, failed_removals
    length = len(current_input)

    if length < 9:
        return current_input # Don't even try to trim

    if length / 3 < total_steps:
        chunk_size = 3  # Trim single operations if input is very small
    else:
        raw_chunk = len(original_input) // total_steps
        chunk_size = max(3, (raw_chunk // 3) * 3) 
    # Compute the starting index, skipping over failed removals
    start_idx = failed_removals * chunk_size
    end_idx = min(start_idx + chunk_size, length)  # Prevent out-of-bounds
    # Remove the calculated chunk
    trimmed_input = current_input[:start_idx] + current_input[end_idx:]
    return trimmed_input

def post_trim(success):
    """Handle trimming results: if successful, keep the trimmed input; otherwise, track the failure."""
    global current_step, current_input, failed_removals
    if success:
        # Update input to permanently remove the trimmed portion
        current_input = trim()
    else:
        # The removal failed, so we just count this failure and move on
        failed_removals += 1

    current_step += 1
    return current_step 
