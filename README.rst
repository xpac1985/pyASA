=====
pyASA
=====

A Python wrapper for the Cisco ASA firewall REST API, aimed at network engineers starting into scripting. Does a lot of validation and other things to make scripting your firewall changes as easy and hassle-free as possible.

**Be aware** - this is an early version and a lot of code might change in the future. Also, the Cisco API tends to be rather unstable and might crash when using it extensively.

============
Installation
============

Install last published version via pip

``pip install pyASA``

=====
Usage
=====

Only in-code documentation so far.

Create an ASA object, supplying at least hostname, username and password for API access.

.. code:: python

    from pyASA.asa import ASA

    myasa = ASA("192.168.17.1", "admin", "cisco")
    rules = myasa.acl.get_rules("MYACL")
    print(rules)

=======
License
=======

MIT.

See LICENSE file for details.
