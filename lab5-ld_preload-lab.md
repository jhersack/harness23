# LD_PRELOAD Lab 

Today we will be looking at reproducing an early CVE in the NCSA HTTPd web server. This is interesting for a couple of reasons:

The vulnerable program is a CGI binary — meaning it takes input through environment variables
The bug is a command injection vulnerability — not a classically “fuzzable” class of bug
It’s a 90’s web server so we get to feel like old-school hackers

A command injection attack comes from a class of software bugs that doesn't involve memory corruption or any other means of taking over the vulnerable program. Instead, it exploits flaws in the programs use of system or exec calls (think command line) to run an arbitrary command on the host. This class of bug is very similar to SQL injection because it is caused by improper escaping (filtering of special characters) and also that it is difficult to find with many traditional software testing methodologies.

The binary we will be looking at within the NCSA HTTPd web server is called phf. phf is a CGI binary and thus takes input from environment variables and even STDIN when handling a POST request. This poses a challenge to us as these input methods are usually totally unsupported by fuzzers. 

The fuzzers you are most likely used to seeing, such as AFL or libfuzzer, take input via files or through special functions. However, we want to instead fuzz environment variables. To do this we will use LD_PRELOAD to modify the behavior of functions such as getenv in order to reroute the fuzz data from our file input to these environment variables.

If you aren’t familiar with LD_PRELOAD, the concept is simple: the dynamic loader allows us to specify a shared library (.so) to fulfill undefined symbols in a binary before the normal shared libraries do. Put another way, LD_PRELOAD allows us to override or hook shared library functions to add custom behavior.
For environment variable fuzzing, our LD_PRELOAD harness will need to do two things:

1. Hook main and load in fuzzed environment variable data from the fuzz file
2. Hook getenv to return the fuzzed environment variable data


Below is pseudo-code for how we can accomplish this:
```
fuzzed_envp: dict
 
def __libc_start_main(main, argc, argv, envp):
   fuzzed = open(argv[-1])
   for env in envp:
       if env.data == "fuzzme":
           env.data = fuzzed.read(ENV_SIZE)
   fuzzed_envp = envp
   return main(argc, argv, envp)
 
def getenv(key):
   return fuzzed_envp[key]
```
With this, we can use the environment variables to signal to our fuzz harness which ones should be fuzzed and which ones shouldn’t. To show how this works, the Mayhemfile for this harness has been included below:

```
project: ncsa-httpd
target: phf
image: $MAYHEM_DOCKER_REGISTRY/ncsahttpd-phf:latest

duration: 90 # normally takes ~30s but let's be safe
advanced_triage: true

cmds:
  - cmd: /build/ncsa-httpd/cgi-bin/phf @@
    env:
      LD_PRELOAD: /build/envfuzz.so
      SERVER_NAME: example.com
      SERVER_PORT: '80'
      SCRIPT_NAME: /phf
      QUERY_STRING: fuzzme
```
Let’s run it in Mayhem…
…and a bug! Unfortunately, this bug is an unexploitable uninitialized variable issue.

This harness, no matter how long we fuzz, will never find the command injection bug! Let’s tackle this in the next section.


# Fuzzing for command injection vulnerabilities
Why can’t we find the command injection? Mayhem, like most fuzzers, is looking for memory corruption or other things that lead to faulting/signaling behavior. Since command injection results in perfectly “valid” behavior, Mayhem doesn’t have any way of detecting it.

Finding command injection bugs will involve another trick but turns out to also be pretty simple to implement. We will do two things: 

predispose the fuzzer to add commands that create “sentinel” files
check for their presence after system or popen commands
To predispose the fuzzer to inject commands, we can use a dictionary with the command string touch /getfuzzed and variants such as ;touch /getfuzzed, \ntouch /getfuzzed, `touch /getfuzzed`, etc. This will make the command show up more in the fuzzed file and if an injection is found, we will know where to look for evidence.

To check for the injection, we will use the same technique as before with LD_PRELOAD harnessing. Below is pseudo-code for how we can accomplish this:

```
def clean_fs():
   rm("/getfuzzed")
 
def check_injection():
   if file_exists("/getfuzzed"):
       print("injection from {}".format(cmd))
       abort()
 
def popen(cmd, rw):
   clean_fs()
   ret = popen_orig(cmd, rw)
   check_injection(cmd)
   return ret
 
def system(cmd):
   clean_fs()
   ret = system_orig(cmd)
   check_injection(cmd)
   return ret
```

In actuality, the popen hook is somewhat more complicated to get correct, as it returns a file pointer (FILE *) with access to the subprocess’s input/output – meaning that the subprocess has usually not finished executing by the end of the popen hook. Therefore, in the real harness, we would need to keep a file pointer to cmd string mapping and check for the file's presence after calls to fread, fwrite, pclose, etc.

Now that we have support for command injection, let's update the Mayhemfile. Note that the only two changes are to add the new LD_PRELOAD and the dictionary.

```
project: ncsa-httpd
target: phf
image: $MAYHEM_DOCKER_REGISTRY/ncsahttpd-phf:latest

duration: 90 # normally takes ~30s but let's be safe
advanced_triage: true

cmds:
  - cmd: /build/ncsa-httpd/cgi-bin/phf @@
    env:
      LD_PRELOAD: /build/envfuzz.so
      SERVER_NAME: example.com
      SERVER_PORT: '80'
      SCRIPT_NAME: /phf
      QUERY_STRING: fuzzme
    dictionary: /build/injection.dict
```

After rerunning in Mayhem, we find a new crash!


# NCSA-HTTPd `phf` command injection example

This repo replicates finding [CVE-1999-0067] with
[fuzzing](https://forallsecure.com/blog/fuzzing-for-command-injection).

## To build

Assuming you just want to build the docker image, run:

```bash
docker build -t forallsecure/ncsahttpd-cve-1999-0067 .
```

## Get from Dockerhub

If you don't want to build locally, you can pull a pre-built image
directly from dockerhub:

```bash
docker pull forallsecure/ncsahttpd-cve-1999-0067
```


## Run under Mayhem

Change to the `ncsahttpd-cve-1999-0067` folder and run:

```bash
mayhem run mayhem/phf
```

and watch Mayhem replicate CVE-1999-0067! It should take very little time
(< 1 minute).

## Run locally

If you want to just run the libfuzzer target locally and you've pulled
the dockerhub image, run:

```
docker run forallsecure/ncsahttpd-cve-1999-0067
```

## POC

We have included a proof of concept output under the `poc`
directory. This bug should be found in around 30 seconds.

Note: Fuzzing has some degree of non-determinism, so when you run
yourself you may not get exactly this file.  This is expected; your
output should still trigger the phf bug.


