FSI Sketch
==========

.. |copy|   unicode:: U+000A9 .. COPYRIGHT SIGN

|copy| 2014 Farsight Security Inc.

Relased under the Apache Software Foundation license.  See LICENSE.txt.
Contains code licensed under the Apache Software Foundation license.  See
COPYRIGHT.txt for details.

About
-----

This is a disk-backed implementation of the Count-Min Sketch algorithm.
The Count-Min Sketch is an Approximate Member Query algorithm, which means
that you can say with certainty that something is not in the set and that
there is a chance of error when you say that something is in the set.  This
algorithm is different from a Bloom filter in that it is a multiset instead
of a set and you can use it to count instances.  It works much like a python 
set except that you can never retrieve keys, only values.  All typical set
operations, except union, are supported.  You will have better results if
you use the add/remove/discard functions instead of the assignment operators
as the former are less disruptive to the internal data structure.

Usage
-----

Print out all lines occurring 5 or more times in a file.

.. code:: python

    from fsisketch import CMSketch

    sketch = CMSketch('example', 'I', 10000)
    for line in open('example.txt'):
        if sketch[line] == 4:
            print (line.rstrip())
        sketch.add(line)

Track when you last saw something.

.. code:: python

    from fsisketch import CMSketch
    from time import time

    sketch = CMSketch('example2', 'd', 10000)
    for key in some_generator():
        now = time()
        if key in sketch:
            print ('Saw "{}" {} seconds ago.'.format(key, now - sketch[key]))
        sketch[key] = now

Find unknown words.

.. code:: python

    from fsisketch import CMSketch

    sketch = CMSketch('example3', 'B', 10000)
    sketch.update(line.rstrip() for line in open('/usr/share/dict/words'))
    new_words = sketch.difference(some_document.split())
