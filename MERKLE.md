## How it works currently

#### thing to redact

```
fruits: ["apple", "banan", "caqui"]
```

#### in SD-CWT

```
# in sd-protected:
salted-array: [["apple", <salt>], ["banan", <salt>], ["caqui", <salt>]]
# in payload
fruits: [h(["apple", <salt>]), h(["banan", <salt>]), h(["caqui", <salt>])]
```

#### in SD-KBT
Say we disclose only "caqui"

```
# in sd-protected:
salted-array: [["caqui", <salt>]]
# in payload
fruits: [h(["apple", <salt>]), h(["banan", <salt>]), h(["caqui", <salt>])]
```

* salted-element size: `["caqui", <salt>]` = 1 + 6 + 17 = 24 bytes
* claim size: `[h(["apple", <salt>]), h(["banan", <salt>]), h(["caqui", <salt>])]` = 1 + 3 * (2 + 34) = 109 bytes
* total: 133 bytes

## How it might work

We map the array in a Merkle Tree like so:

```
       *ABC
         |
       .-+-.
      /     \
    *AB     *C
    / \     / \
  *A  *B   *C  []
```

where `*A` is `h(["apple", <salt>])` and `*AB` is `h(["apple", <salt>] | ["banan", <salt>])`

#### in SD-CWT

```
# in sd-protected:
salted-array: [["apple", <salt>], ["banan", <salt>], ["caqui", <salt>]]
# in payload
fruits: #6.TBD([*ABCD, 3])
```

We put in the payload only the hash of the root node of the Merkle Tree as well as the number of nodes in the tree.

#### in SD-KBT

```
# in sd-protected:
salted-array: [[["caqui", <salt>], *CD]]
# in payload
fruits: #6.TBD([*ABCD, 3])
```

* salted-element size: `[["caqui", <salt>], *CD]` = 1 + (6 + 17) + 34 = 58 bytes
* claim size: `#6.TBD42([*ABCD, 3])` = 1 + 1 + 34 + 1 = 37 bytes
* total: 95 bytes

## Benefits

* 30% smaller for an array of 3, the larger the array the smaller the size
* You get zero cost decoys for your collections if you pad to the next power of 2 !
