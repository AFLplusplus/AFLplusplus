import sys
import json
import re
from collections import defaultdict
# import pygraphviz as pgv

gram_data = None
state_count = 1
pda = []
worklist = []
state_stacks = {} 

# === If user provides upper bound on the stack size during FSA creation ===
# Specifies the upper bound to which the stack is allowed to grow
# If for any generated state, the stack size is >= stack_limit then this
# state is not expanded further.
stack_limit = None 
# Holds the set of unexpanded rules owing to the user-passed stack constraint limit
unexpanded_rules = set()

def main(grammar, limit):
    global worklist, gram_data, stack_limit
    current = '0'
    stack_limit = limit
    if stack_limit:
        print ('[X] Operating in bounded stack mode')

    with open(grammar, 'r') as fd:
        gram_data = json.load(fd)
    start_symbol = gram_data["Start"][0]
    worklist.append([current, [start_symbol]])
    # print (grammar)
    filename = (grammar.split('/')[-1]).split('.')[0]
    

    while worklist:
        # Take an element from the worklist
        # print ('================')
        # print ('Worklist:', worklist)
        element = worklist.pop(0)
        prep_transitions(element)
    
    pda_file = filename + '_transition.json'
    graph_file = filename + '.png'
    # print ('XXXXXXXXXXXXXXXX')
    # print ('PDA file:%s Png graph file:%s' % (pda_file, graph_file))
    # XXX Commented out because visualization of current version of PHP causes segfault
    # Create the graph and dump the transitions to a file
    # create_graph(filename)
    transformed = postprocess()
    with open(filename + '_automata.json', 'w+') as fd:
        json.dump(transformed, fd)
    with open(filename + '_transition.json', 'w+') as fd:
        json.dump(pda, fd)
    if not unexpanded_rules:
        print ('[X] No unexpanded rules, absolute FSA formed')
        exit(0)
    else:
        print ('[X] Certain rules were not expanded due to stack size limit. Inexact approximation has been created and the disallowed rules have been put in {}_disallowed.json'.format(filename))
        print ('[X] Number of unexpanded rules:', len(unexpanded_rules))
        with open(filename + '_disallowed.json', 'w+') as fd:
            json.dump(list(unexpanded_rules), fd)

def create_graph(filename):
    '''
    Creates a DOT representation of the PDA
    '''
    global pda
    G = pgv.AGraph(strict = False, directed = True)
    for transition in pda:
        print ('Transition:', transition)
        G.add_edge(transition['source'], transition['dest'], 
                label = 'Term:{}'.format(transition['terminal']))
    G.layout(prog = 'dot')
    print ('Do it up 2')
    G.draw(filename + '.png')

def prep_transitions(element):
    '''
    Generates transitions
    '''
    global gram_data, state_count, pda, worklist, state_stacks, stack_limit, unexpanded_rules
    state = element[0]
    try:
        nonterminal = element[1][0] 
    except IndexError:
        # Final state was encountered, pop from worklist without doing anything
        return
    rules = gram_data[nonterminal]
    count = 1
    for rule in rules:
        isRecursive  = False
        # print ('Current state:', state)
        terminal, ss, termIsRegex = tokenize(rule)
        transition = get_template()
        transition['trigger'] = '_'.join([state, str(count)])
        transition['source'] = state
        transition['dest'] = str(state_count) 
        transition['ss'] = ss 
        transition['terminal'] = terminal
        transition['rule'] = "{} -> {}".format(nonterminal, rule )
        if termIsRegex:
            transition['termIsRegex'] = True
        
        # Creating a state stack for the new state
        try:
            state_stack = state_stacks[state][:]
        except:
            state_stack = []
        if len(state_stack):
            state_stack.pop(0)
        if ss:
            for symbol in ss[::-1]:
                state_stack.insert(0, symbol)
        transition['stack'] = state_stack 

        # Check if a recursive transition state being created, if so make a backward
        # edge and don't add anything to the worklist
        # print (state_stacks)
        if state_stacks:
            for state_element, stack in state_stacks.items():
                # print ('Stack:', sorted(stack))
                # print ('State stack:', sorted(state_stack))
                if sorted(stack) == sorted(state_stack):
                    transition['dest'] = state_element
                    # print ('Recursive:', transition)
                    pda.append(transition)
                    count += 1
                    isRecursive = True
                    break 
        # If a recursive transition exercised don't add the same transition as a new
        # edge, continue onto the next transitions
        if isRecursive:
            continue
            
        # If the generated state has a stack size > stack_limit then that state is abandoned
        # and not added to the FSA or the worklist for further expansion
        if stack_limit:
            if (len(transition['stack']) > stack_limit):
                unexpanded_rules.add(transition['rule'])
                continue

        # Create transitions for the non-recursive relations and add to the worklist
        # print ('Normal:', transition)
        # print ('State2:', state)
        pda.append(transition)
        worklist.append([transition['dest'], transition['stack']])
        state_stacks[transition['dest']] = state_stack
        state_count += 1
        count += 1

def tokenize(rule):
    '''
    Gets the terminal and the corresponding stack symbols from a rule in GNF form
    '''
    pattern = re.compile("([r])*\'([\s\S]+)\'([\s\S]*)")
    terminal = None
    ss = None
    termIsRegex = False
    match = pattern.match(rule)
    if match.group(1):
        termIsRegex = True
    if match.group(2):
        terminal = match.group(2)
    else:
        raise AssertionError("Rule is not in GNF form")

    if match.group(3):
        ss = (match.group(3)).split()

    return terminal, ss, termIsRegex

def get_template():
    transition_template = {
            'trigger':None,
            'source': None,
            'dest': None,
            'termIsRegex': False,
            'terminal' : None,
            'stack': []
            }
    return transition_template

def postprocess():
    '''
    Creates a representation to be passed on to the C-module
    '''
    global pda
    final_struct = {}
    memoized = defaultdict(list)
    # Supporting data structures for if stack limit is imposed
    culled_pda = []
    culled_final = []
    num_transitions = 0 # Keep track of number of transitions


    states, final, initial = _get_states()

    print (initial)
    assert len(initial) == 1, 'More than one init state found'

    # Cull transitions to states which were not expanded owing to the stack limit
    if stack_limit:

        blocklist = []
        for final_state in final:
            for transition in pda:
                if (transition["dest"] == final_state) and (len(transition["stack"]) > 0):
                    blocklist.append(transition["dest"])
                    continue
                else:
                    culled_pda.append(transition)
        
        culled_final = [state for state in final if state not in blocklist]

        assert len(culled_final) == 1, 'More than one final state found'

        for transition in culled_pda:
            state = transition["source"]
            if transition["dest"] in blocklist:
                    continue 
            num_transitions += 1
            memoized[state].append([transition["trigger"], transition["dest"], 
                transition["terminal"]])
        final_struct["init_state"] = initial
        final_struct["final_state"] = culled_final[0]
        # The reason we do this is because when states are culled, the indexing is
        # still relative to the actual number of states hence we keep numstates recorded
        # as the original number of states
        print ('[X] Actual Number of states:', len(memoized.keys()))
        print ('[X] Number of transitions:', num_transitions)
        print ('[X] Original Number of states:', len(states))
        final_struct["numstates"] = len(states) 
        final_struct["pda"] = memoized
        return final_struct
    
    # Running FSA construction in exact approximation mode and postprocessing it like so
    for transition in pda:
       state = transition["source"]
       memoized[state].append([transition["trigger"], transition["dest"], 
           transition["terminal"]])

    final_struct["init_state"] = initial
    final_struct["final_state"] = final[0]
    print ('[X] Actual Number of states:', len(memoized.keys()))
    final_struct["numstates"] = len(memoized.keys()) 
    final_struct["pda"] = memoized
    return final_struct


def _get_states():
    source = set()
    dest = set()
    global pda
    for transition in pda:
        source.add(transition["source"])
        dest.add(transition["dest"])
    source_copy = source.copy()
    source_copy.update(dest)
    return list(source_copy), list(dest.difference(source)), str(''.join(list(source.difference(dest))))

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description = 'Script to convert GNF grammar to PDA')
    parser.add_argument(
            '--gf',
            type = str,
            help = 'Location of GNF grammar')
    parser.add_argument(
            '--limit',
            type = int,
            default = None,
            help = 'Specify the upper bound for the stack size')
    args = parser.parse_args()
    main(args.gf, args.limit)
