# Proj3b - Stateful Active Application-Layer Firewall
    UC Berkeley CS 168, Fall 2014
    CS168 Project 3b
    (Version 1.0)
    Due: 11:59:59 am (at noon), December 3th, 2014 (hard deadline)
    Chang Lan Shoumik Palkar Sangjin Han

## Overview
In this project, you will implement a basic firewall running at end hosts. A firewall is a “security system that controls the incoming and outgoing network traffic by analyzing the data packets and determining whether they should be allowed through or not, based on a rule set” [Wikipedia]. Unlike the previous projects of this course, where you worked in simulated environments, you will deal with real packets in a Linux-based virtual machine (VM) for this project.

Recall that in 3a, you implemented a stateless passive firewall: that is, your firewall could do its job by considering each packet individually, and it did not generate traffic.

In 3b, you will be extending your solution for 3a to make a stateful active application-layer firewall. You will use the same framework, VM, test harnesses, tools, and as in 3a. Now, your firewall should generate packets in response to denied packets. Upon completing this part, you should:

- Be familiar with the HTTP and DNS protocols.
- Understand the difference between stateful vs. stateless, active vs. passive firewalls.

Besides writing code, you will need to (and should) spend a lot of time to understand protocol specifications, to design algorithms, and to test your application. Start working on the project as soon as possible.

You will likely find the supplementary document from 3a useful for this part, as well. http://www-inst.eecs.berkeley.edu/~cs168/fa14/projects/project3a/supplement.pdf

Good luck, and have fun.

Proj3b - Stateful Active Application-Layer Firewall Specs [here](/specs/Proj3b-StatefulActiveFirewall-Specs.pdf)