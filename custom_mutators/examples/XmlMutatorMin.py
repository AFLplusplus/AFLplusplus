#!/usr/bin/python

""" Mutation of XML documents, should be called from one of its wrappers (CLI, AFL, ...) """

from __future__ import print_function
from copy import deepcopy
from lxml import etree as ET
import random, re, io


###########################
# The XmlMutatorMin class #
###########################


class XmlMutatorMin:

    """
    Optionals parameters:
        seed        Seed used by the PRNG (default: "RANDOM")
        verbose     Verbosity (default: False)
    """

    def __init__(self, seed="RANDOM", verbose=False):

        """ Initialize seed, database and mutators """

        # Verbosity
        self.verbose = verbose

        # Initialize PRNG
        self.seed = str(seed)
        if self.seed == "RANDOM":
            random.seed()
        else:
            if self.verbose:
                print("Static seed '%s'" % self.seed)
            random.seed(self.seed)

        # Initialize input and output documents
        self.input_tree = None
        self.tree = None

        # High-level mutators (no database needed)
        hl_mutators_delete = [
            "del_node_and_children",
            "del_node_but_children",
            "del_attribute",
            "del_content",
        ]  # Delete items
        hl_mutators_fuzz = ["fuzz_attribute"]  # Randomly change attribute values

        # Exposed mutators
        self.hl_mutators_all = hl_mutators_fuzz + hl_mutators_delete

    def __parse_xml(self, xml):

        """ Parse an XML string. Basic wrapper around lxml.parse() """

        try:
            # Function parse() takes care of comments / DTD / processing instructions / ...
            tree = ET.parse(io.BytesIO(xml))
        except ET.ParseError:
            raise RuntimeError("XML isn't well-formed!")
        except LookupError as e:
            raise RuntimeError(e)

        # Return a document wrapper
        return tree

    def __exec_among(self, module, functions, min_times, max_times):

        """ Randomly execute $functions between $min and $max times """

        for i in xrange(random.randint(min_times, max_times)):
            # Function names are mangled because they are "private"
            getattr(module, "_XmlMutatorMin__" + random.choice(functions))()

    def __serialize_xml(self, tree):

        """ Serialize a XML document. Basic wrapper around lxml.tostring() """

        return ET.tostring(
            tree, with_tail=False, xml_declaration=True, encoding=tree.docinfo.encoding
        )

    def __ver(self, version):

        """ Helper for displaying lxml version numbers """

        return ".".join(map(str, version))

    def reset(self):

        """ Reset the mutator """

        self.tree = deepcopy(self.input_tree)

    def init_from_string(self, input_string):

        """ Initialize the mutator from a XML string """

        # Get a pointer to the top-element
        self.input_tree = self.__parse_xml(input_string)

        # Get a working copy
        self.tree = deepcopy(self.input_tree)

    def save_to_string(self):

        """ Return the current XML document as UTF-8 string """

        # Return a text version of the tree
        return self.__serialize_xml(self.tree)

    def __pick_element(self, exclude_root_node=False):

        """ Pick a random element from the current document """

        # Get a list of all elements, but nodes like PI and comments
        elems = list(self.tree.getroot().iter(tag=ET.Element))

        # Is the root node excluded?
        if exclude_root_node:
            start = 1
        else:
            start = 0

        # Pick a random element
        try:
            elem_id = random.randint(start, len(elems) - 1)
            elem = elems[elem_id]
        except ValueError:
            # Should only occurs if "exclude_root_node = True"
            return (None, None)

        return (elem_id, elem)

    def __fuzz_attribute(self):

        """ Fuzz (part of) an attribute value """

        # Select a node to modify
        (rand_elem_id, rand_elem) = self.__pick_element()

        # Get all the attributes
        attribs = rand_elem.keys()

        # Is there attributes?
        if len(attribs) < 1:
            if self.verbose:
                print("No attribute: can't replace!")
            return

        # Pick a random attribute
        rand_attrib_id = random.randint(0, len(attribs) - 1)
        rand_attrib = attribs[rand_attrib_id]

        # We have the attribute to modify
        # Get its value
        attrib_value = rand_elem.get(rand_attrib)
        # print("- Value: " + attrib_value)

        # Should we work on the whole value?
        func_call = "(?P<func>[a-zA-Z:\-]+)\((?P<args>.*?)\)"
        p = re.compile(func_call)
        l = p.findall(attrib_value)
        if random.choice((True, False)) and l:
            # Randomly pick one the function calls
            (func, args) = random.choice(l)
            # Split by "," and randomly pick one of the arguments
            value = random.choice(args.split(","))
            # Remove superfluous characters
            unclean_value = value
            value = value.strip(" ").strip("'")
            # print("Selected argument: [%s]" % value)
        else:
            value = attrib_value

        # For each type, define some possible replacement values
        choices_number = (
            "0",
            "11111",
            "-128",
            "2",
            "-1",
            "1/3",
            "42/0",
            "1094861636 idiv 1.0",
            "-1123329771506872 idiv 3.8",
            "17=$numericRTF",
            str(3 + random.randrange(0, 100)),
        )

        choices_letter = (
            "P" * (25 * random.randrange(1, 100)),
            "%s%s%s%s%s%s",
            "foobar",
        )

        choices_alnum = (
            "Abc123",
            "020F0302020204030204",
            "020F0302020204030204" * (random.randrange(5, 20)),
        )

        # Fuzz the value
        if random.choice((True, False)) and value == "":

            # Empty
            new_value = value

        elif random.choice((True, False)) and value.isdigit():

            # Numbers
            new_value = random.choice(choices_number)

        elif random.choice((True, False)) and value.isalpha():

            # Letters
            new_value = random.choice(choices_letter)

        elif random.choice((True, False)) and value.isalnum():

            # Alphanumeric
            new_value = random.choice(choices_alnum)

        else:

            # Default type
            new_value = random.choice(choices_alnum + choices_letter + choices_number)

        # If we worked on a substring, apply changes to the whole string
        if value != attrib_value:
            # No ' around empty values
            if new_value != "" and value != "":
                new_value = "'" + new_value + "'"
            # Apply changes
            new_value = attrib_value.replace(unclean_value, new_value)

        # Log something
        if self.verbose:
            print(
                "Fuzzing attribute #%i '%s' of tag #%i '%s'"
                % (rand_attrib_id, rand_attrib, rand_elem_id, rand_elem.tag)
            )

        # Modify the attribute
        rand_elem.set(rand_attrib, new_value.decode("utf-8"))

    def __del_node_and_children(self):

        """High-level minimizing mutator
        Delete a random node and its children (i.e. delete a random tree)"""

        self.__del_node(True)

    def __del_node_but_children(self):

        """High-level minimizing mutator
        Delete a random node but its children (i.e. link them to the parent of the deleted node)"""

        self.__del_node(False)

    def __del_node(self, delete_children):

        """ Called by the __del_node_* mutators """

        # Select a node to modify (but the root one)
        (rand_elem_id, rand_elem) = self.__pick_element(exclude_root_node=True)

        # If the document includes only a top-level element
        # Then we can't pick a element (given that "exclude_root_node = True")

        # Is the document deep enough?
        if rand_elem is None:
            if self.verbose:
                print("Can't delete a node: document not deep enough!")
            return

        # Log something
        if self.verbose:
            but_or_and = "and" if delete_children else "but"
            print(
                "Deleting tag #%i '%s' %s its children"
                % (rand_elem_id, rand_elem.tag, but_or_and)
            )

        if delete_children is False:
            # Link children of the random (soon to be deleted) node to its parent
            for child in rand_elem:
                rand_elem.getparent().append(child)

        # Remove the node
        rand_elem.getparent().remove(rand_elem)

    def __del_content(self):

        """High-level minimizing mutator
        Delete the attributes and children of a random node"""

        # Select a node to modify
        (rand_elem_id, rand_elem) = self.__pick_element()

        # Log something
        if self.verbose:
            print("Reseting tag #%i '%s'" % (rand_elem_id, rand_elem.tag))

        # Reset the node
        rand_elem.clear()

    def __del_attribute(self):

        """High-level minimizing mutator
        Delete a random attribute from a random node"""

        # Select a node to modify
        (rand_elem_id, rand_elem) = self.__pick_element()

        # Get all the attributes
        attribs = rand_elem.keys()

        # Is there attributes?
        if len(attribs) < 1:
            if self.verbose:
                print("No attribute: can't delete!")
            return

        # Pick a random attribute
        rand_attrib_id = random.randint(0, len(attribs) - 1)
        rand_attrib = attribs[rand_attrib_id]

        # Log something
        if self.verbose:
            print(
                "Deleting attribute #%i '%s' of tag #%i '%s'"
                % (rand_attrib_id, rand_attrib, rand_elem_id, rand_elem.tag)
            )

        # Delete the attribute
        rand_elem.attrib.pop(rand_attrib)

    def mutate(self, min=1, max=5):

        """ Execute some high-level mutators between $min and $max times, then some medium-level ones """

        # High-level mutation
        self.__exec_among(self, self.hl_mutators_all, min, max)
