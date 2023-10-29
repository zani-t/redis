# Redis
This is an implementation of the Redis data storage framework developed by Salvatore Sanfilippo and Redis Labs. I wrote this under the guidance of James Smith's tutorial:
https://build-your-own.org/#section-redis 

**What is Redis?**
While most databases maintain persistence of data through storage and access on a hard disk, Redis popularized the use of database storage through memory, allowing for fast and efficient access, as well as its simultaneous use as a cache. As opposed to a query-based system of accessing and modifying data, Redis also prioritizes individual operations to data described in commands. Nowadays it is used by numerous major social media and commercial platforms.

**Implementation**
The code in this repository replicates some of the basic elements of Redis. It supports strings, integers, doubles and Redis's sorted set. It's currently configured to run on given ports of localhost. CMake is used to compile executables and tests of data structures. In the repository are the following files:
 - client: Interface for user to connect to the server and manipulate data by sending commands. Commands are converted to a specific protocol.
 - server: Established connections with clients and processes commands. Upon completion it will send back to the user.
 - hashtable: Implementation of a hash map containing two hash tables (with chaining collision resolution) for key-value storage. Values are moved between tables upon resizing.
 - avl: AVL tree implementation.
 - zset: Sorted set (ZSet) implementation using the hash map in conjunction with an AVL tree for persistent sorting of data.
 - heap: Heap implementation for storage of TTLs for cache data.
 - list (dlist): Linked list implementation for storage of connection timeouts.
 - thread_pool: Thread pool implemented to freely work on the deletion of nodes and restructuring of the sorted set without intruding heavily on memory usage. Producer threads create tasks while consumer threads wait for a task and then operate.