### Data type

There are four collection data types in the Python programming language:

- **[List](https://www.w3schools.com/python/python_lists.asp)** is a collection which is ordered and changeable. Allows duplicate members.
- **[Tuple](https://www.w3schools.com/python/python_tuples.asp)** is a collection which is ordered and unchangeable. Allows duplicate members.
- **Set** is a collection which is unordered, unchangeable*, and unindexed. No duplicate members.
- **[Dictionary](https://www.w3schools.com/python/python_dictionaries.asp)** is a collection which is ordered** and changeable. No duplicate members.


| x = ["apple", "banana", "cherry"]            | list      |
| -------------------------------------------- | --------- |
| x = ("apple", "banana", "cherry")            | tuple     |
| x = range(6)                                 | range     |
| x = {"name" : "John", "age" : 36}            | dict      |
| x = {"apple", "banana", "cherry"}            | set       |
| x = frozenset({"apple", "banana", "cherry"}) | frozenset |
| x = b"Hello"                                 | bytes     |

---
print(random.randrange(1, 10))

txt = "The best things in life are free!"  
print("free" in txt) >>> True

The `strip()` method removes any whitespace from the beginning or the end

x = str(3)    # x will be '3'  
y = int(3)    # y will be 3  
z = float(3)  # z will be 3.0

The `replace()` method replaces a string with another string:
a = "Hello, World!"  
print(a.replace("H", "J"))

The `split()` method splits the string into substrings if it finds instances of the separator:
a = "Hello, World!"  
print(a.split(",")) # returns ['Hello', ' World!']

Create an f-string:
age = 36  
txt = f"My name is John, I am {age}"  
print(txt)

The following will return False:
bool(False)  
bool(None)  
bool(0)  
bool("")  
bool(())  
bool([])  
bool({})

the `isinstance()` function, which can be used to determine if an object is of a certain data type:
x = 200  
print(isinstance(x, int))

| print(x := 3) | x = 3  <br>print(x) |
| ------------- | ------------------- |

(x is y)
(x is not y)
(x in y)
(x not in y)




The `pop()` method removes the specified index.
The `remove()` method removes the specified item.
To add an item to the end of the list, use the append() method
The `clear()` method empties the list.

The `insert()` method inserts an item at the specified index:
thislist = ["apple", "banana", "cherry" ] 
thislist.insert(2, "watermelon")  
print(thislist) >>>> ["apple", "banana", "watermelon" ] 

To append elements from _another list_ to the current list, use the `extend()` method.
thislist = ["apple", "banana", "cherry"]  
tropical = ["mango", "pineapple", "papaya"]  
thislist.extend(tropical)

The `del` keyword also removes the specified index:
del thislist[0]


A short hand `for` loop that will print all items in a list:
thislist = ["apple", "banana", "cherry"]  
[print(x) for x in thislist]


Assign the rest of the values as a list called "red":
fruits = ("apple", "banana", "cherry", "strawberry", "raspberry")  
(green, yellow, \*red) = fruits

## Join Sets

There are several ways to join two or more sets in Python.

The `union()` and `update()` methods joins all items from both sets.

The `intersection()` method keeps ONLY the duplicates.

The `difference()` method keeps the items from the first set that are not in the other set(s).

The `symmetric_difference()` method keeps all items EXCEPT the duplicates.




---

| Method                                                                         | Description                                                                                   |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| [capitalize()](https://www.w3schools.com/python/ref_string_capitalize.asp)     | Converts the first character to upper case                                                    |
| [casefold()](https://www.w3schools.com/python/ref_string_casefold.asp)         | Converts string into lower case                                                               |
| [center()](https://www.w3schools.com/python/ref_string_center.asp)             | Returns a centered string                                                                     |
| [count()](https://www.w3schools.com/python/ref_string_count.asp)               | Returns the number of times a specified value occurs in a string                              |
| [encode()](https://www.w3schools.com/python/ref_string_encode.asp)             | Returns an encoded version of the string                                                      |
| [endswith()](https://www.w3schools.com/python/ref_string_endswith.asp)         | Returns true if the string ends with the specified value                                      |
| [expandtabs()](https://www.w3schools.com/python/ref_string_expandtabs.asp)     | Sets the tab size of the string                                                               |
| [find()](https://www.w3schools.com/python/ref_string_find.asp)                 | Searches the string for a specified value and returns the position of where it was found      |
| [format()](https://www.w3schools.com/python/ref_string_format.asp)             | Formats specified values in a string                                                          |
| format_map()                                                                   | Formats specified values in a string                                                          |
| [index()](https://www.w3schools.com/python/ref_string_index.asp)               | Searches the string for a specified value and returns the position of where it was found      |
| [isalnum()](https://www.w3schools.com/python/ref_string_isalnum.asp)           | Returns True if all characters in the string are alphanumeric                                 |
| [isalpha()](https://www.w3schools.com/python/ref_string_isalpha.asp)           | Returns True if all characters in the string are in the alphabet                              |
| [isascii()](https://www.w3schools.com/python/ref_string_isascii.asp)           | Returns True if all characters in the string are ascii characters                             |
| [isdecimal()](https://www.w3schools.com/python/ref_string_isdecimal.asp)       | Returns True if all characters in the string are decimals                                     |
| [isdigit()](https://www.w3schools.com/python/ref_string_isdigit.asp)           | Returns True if all characters in the string are digits                                       |
| [isidentifier()](https://www.w3schools.com/python/ref_string_isidentifier.asp) | Returns True if the string is an identifier                                                   |
| [islower()](https://www.w3schools.com/python/ref_string_islower.asp)           | Returns True if all characters in the string are lower case                                   |
| [isnumeric()](https://www.w3schools.com/python/ref_string_isnumeric.asp)       | Returns True if all characters in the string are numeric                                      |
| [isprintable()](https://www.w3schools.com/python/ref_string_isprintable.asp)   | Returns True if all characters in the string are printable                                    |
| [isspace()](https://www.w3schools.com/python/ref_string_isspace.asp)           | Returns True if all characters in the string are whitespaces                                  |
| [istitle()](https://www.w3schools.com/python/ref_string_istitle.asp)           | Returns True if the string follows the rules of a title                                       |
| [isupper()](https://www.w3schools.com/python/ref_string_isupper.asp)           | Returns True if all characters in the string are upper case                                   |
| [join()](https://www.w3schools.com/python/ref_string_join.asp)                 | Joins the elements of an iterable to the end of the string                                    |
| [ljust()](https://www.w3schools.com/python/ref_string_ljust.asp)               | Returns a left justified version of the string                                                |
| [lower()](https://www.w3schools.com/python/ref_string_lower.asp)               | Converts a string into lower case                                                             |
| [lstrip()](https://www.w3schools.com/python/ref_string_lstrip.asp)             | Returns a left trim version of the string                                                     |
| [maketrans()](https://www.w3schools.com/python/ref_string_maketrans.asp)       | Returns a translation table to be used in translations                                        |
| [partition()](https://www.w3schools.com/python/ref_string_partition.asp)       | Returns a tuple where the string is parted into three parts                                   |
| [replace()](https://www.w3schools.com/python/ref_string_replace.asp)           | Returns a string where a specified value is replaced with a specified value                   |
| [rfind()](https://www.w3schools.com/python/ref_string_rfind.asp)               | Searches the string for a specified value and returns the last position of where it was found |
| [rindex()](https://www.w3schools.com/python/ref_string_rindex.asp)             | Searches the string for a specified value and returns the last position of where it was found |
| [rjust()](https://www.w3schools.com/python/ref_string_rjust.asp)               | Returns a right justified version of the string                                               |
| [rpartition()](https://www.w3schools.com/python/ref_string_rpartition.asp)     | Returns a tuple where the string is parted into three parts                                   |
| [rsplit()](https://www.w3schools.com/python/ref_string_rsplit.asp)             | Splits the string at the specified separator, and returns a list                              |
| [rstrip()](https://www.w3schools.com/python/ref_string_rstrip.asp)             | Returns a right trim version of the string                                                    |
| [split()](https://www.w3schools.com/python/ref_string_split.asp)               | Splits the string at the specified separator, and returns a list                              |
| [splitlines()](https://www.w3schools.com/python/ref_string_splitlines.asp)     | Splits the string at line breaks and returns a list                                           |
| [startswith()](https://www.w3schools.com/python/ref_string_startswith.asp)     | Returns true if the string starts with the specified value                                    |
| [strip()](https://www.w3schools.com/python/ref_string_strip.asp)               | Returns a trimmed version of the string                                                       |
| [swapcase()](https://www.w3schools.com/python/ref_string_swapcase.asp)         | Swaps cases, lower case becomes upper case and vice versa                                     |
| [title()](https://www.w3schools.com/python/ref_string_title.asp)               | Converts the first character of each word to upper case                                       |
| [translate()](https://www.w3schools.com/python/ref_string_translate.asp)       | Returns a translated string                                                                   |
| [upper()](https://www.w3schools.com/python/ref_string_upper.asp)               | Converts a string into upper case                                                             |
| [zfill()](https://www.w3schools.com/python/ref_string_zfill.asp)               | Fills the string with a specified number of 0 values at the beginning                         |


| Method                                                             | Description                                                                  |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| [append()](https://www.w3schools.com/python/ref_list_append.asp)   | Adds an element at the end of the list                                       |
| [clear()](https://www.w3schools.com/python/ref_list_clear.asp)     | Removes all the elements from the list                                       |
| [copy()](https://www.w3schools.com/python/ref_list_copy.asp)       | Returns a copy of the list                                                   |
| [count()](https://www.w3schools.com/python/ref_list_count.asp)     | Returns the number of elements with the specified value                      |
| [extend()](https://www.w3schools.com/python/ref_list_extend.asp)   | Add the elements of a list (or any iterable), to the end of the current list |
| [index()](https://www.w3schools.com/python/ref_list_index.asp)     | Returns the index of the first element with the specified value              |
| [insert()](https://www.w3schools.com/python/ref_list_insert.asp)   | Adds an element at the specified position                                    |
| [pop()](https://www.w3schools.com/python/ref_list_pop.asp)         | Removes the element at the specified position                                |
| [remove()](https://www.w3schools.com/python/ref_list_remove.asp)   | Removes the item with the specified value                                    |
| [reverse()](https://www.w3schools.com/python/ref_list_reverse.asp) | Reverses the order of the list                                               |
| [sort()](https://www.w3schools.com/python/ref_list_sort.asp)       | Sorts the list                                                               |

| Method                                                          | Description                                                                             |
| --------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| [count()](https://www.w3schools.com/python/ref_tuple_count.asp) | Returns the number of times a specified value occurs in a tuple                         |
| [index()](https://www.w3schools.com/python/ref_tuple_index.asp) | Searches the tuple for a specified value and returns the position of where it was found |


| Method                                                                                                    | Shortcut                                                                       | Description                                                                    |
| --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| [add()](https://www.w3schools.com/python/ref_set_add.asp)                                                 |                                                                                | Adds an element to the set                                                     |
| [clear()](https://www.w3schools.com/python/ref_set_clear.asp)                                             |                                                                                | Removes all the elements from the set                                          |
| [copy()](https://www.w3schools.com/python/ref_set_copy.asp)                                               |                                                                                | Returns a copy of the set                                                      |
| [difference()](https://www.w3schools.com/python/ref_set_difference.asp)                                   | [-](https://www.w3schools.com/python/ref_set_difference.asp)                   | Returns a set containing the difference between two or more sets               |
| [difference_update()](https://www.w3schools.com/python/ref_set_difference_update.asp)                     | [-=](https://www.w3schools.com/python/ref_set_difference_update.asp)           | Removes the items in this set that are also included in another, specified set |
| [discard()](https://www.w3schools.com/python/ref_set_discard.asp)                                         |                                                                                | Remove the specified item                                                      |
| [intersection()](https://www.w3schools.com/python/ref_set_intersection.asp)                               | [&](https://www.w3schools.com/python/ref_set_intersection.asp)                 | Returns a set, that is the intersection of two other sets                      |
| [intersection_update()](https://www.w3schools.com/python/ref_set_intersection_update.asp)                 | [&=](https://www.w3schools.com/python/ref_set_intersection_update.asp)         | Removes the items in this set that are not present in other, specified set(s)  |
| [isdisjoint()](https://www.w3schools.com/python/ref_set_isdisjoint.asp)                                   |                                                                                | Returns whether two sets have a intersection or not                            |
| [issubset()](https://www.w3schools.com/python/ref_set_issubset.asp)                                       | [<=](https://www.w3schools.com/python/ref_set_issubset.asp)                    | Returns whether another set contains this set or not                           |
|                                                                                                           | [<](https://www.w3schools.com/python/ref_set_issubset.asp)                     | Returns whether all items in this set is present in other, specified set(s)    |
| [issuperset()](https://www.w3schools.com/python/ref_set_issuperset.asp)                                   | [>=](https://www.w3schools.com/python/ref_set_issuperset.asp)                  | Returns whether this set contains another set or not                           |
|                                                                                                           | [>](https://www.w3schools.com/python/ref_set_issuperset.asp)                   | Returns whether all items in other, specified set(s) is present in this set    |
| [pop()](https://www.w3schools.com/python/ref_set_pop.asp)                                                 |                                                                                | Removes an element from the set                                                |
| [remove()](https://www.w3schools.com/python/ref_set_remove.asp)                                           |                                                                                | Removes the specified element                                                  |
| [symmetric_difference()](https://www.w3schools.com/python/ref_set_symmetric_difference.asp)               | [^](https://www.w3schools.com/python/ref_set_symmetric_difference.asp)         | Returns a set with the symmetric differences of two sets                       |
| [symmetric_difference_update()](https://www.w3schools.com/python/ref_set_symmetric_difference_update.asp) | [^=](https://www.w3schools.com/python/ref_set_symmetric_difference_update.asp) | Inserts the symmetric differences from this set and another                    |
| [union()](https://www.w3schools.com/python/ref_set_union.asp)                                             | [\|](https://www.w3schools.com/python/ref_set_union.asp)                       | Return a set containing the union of sets                                      |
| [update()](https://www.w3schools.com/python/ref_set_update.asp)                                           | [\|=](https://www.w3schools.com/python/ref_set_update.asp)                     | Update the set with the union of this set and others                           |


| Method                                                                         | Description                                                                                                 |
| ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| [clear()](https://www.w3schools.com/python/ref_dictionary_clear.asp)           | Removes all the elements from the dictionary                                                                |
| [copy()](https://www.w3schools.com/python/ref_dictionary_copy.asp)             | Returns a copy of the dictionary                                                                            |
| [fromkeys()](https://www.w3schools.com/python/ref_dictionary_fromkeys.asp)     | Returns a dictionary with the specified keys and value                                                      |
| [get()](https://www.w3schools.com/python/ref_dictionary_get.asp)               | Returns the value of the specified key                                                                      |
| [items()](https://www.w3schools.com/python/ref_dictionary_items.asp)           | Returns a list containing a tuple for each key value pair                                                   |
| [keys()](https://www.w3schools.com/python/ref_dictionary_keys.asp)             | Returns a list containing the dictionary's keys                                                             |
| [pop()](https://www.w3schools.com/python/ref_dictionary_pop.asp)               | Removes the element with the specified key                                                                  |
| [popitem()](https://www.w3schools.com/python/ref_dictionary_popitem.asp)       | Removes the last inserted key-value pair                                                                    |
| [setdefault()](https://www.w3schools.com/python/ref_dictionary_setdefault.asp) | Returns the value of the specified key. If the key does not exist: insert the key, with the specified value |
| [update()](https://www.w3schools.com/python/ref_dictionary_update.asp)         | Updates the dictionary with the specified key-value pairs                                                   |
| [values()](https://www.w3schools.com/python/ref_dictionary_values.asp)         | Returns a list of all the values in the dictionary                                                          |

---

print(3 << 2)

The << operator inserts the specified number of 0's (in this case 2) from the right and let the same amount of leftmost bits fall off:
If you push 00 in from the left:
 3 = 0000000000000011
becomes
12 = 0000000000001100


print(6 ^ 3)

The ^ operator compares each bit and set it to 1 if only one is 1, otherwise (if both are 1 or both are 0) it is set to 0:
6 = 0000000000000110
3 = 0000000000000011
5 = 0000000000000101


print(~3)

The ~ operator inverts each bit (0 becomes 1 and 1 becomes 0).
Inverted 3 becomes -4:
 3 = 0000000000000011
-4 = 1111111111111100

---
 Copy a List
 thislist = ["apple", "banana", "cherry"]  
 
mylist = thislist.copy()
mylist = list(thislist)
mylist = thislist[:]

---

https://docs.pwntools.com/en/stable/

https://github.com/Gallopsled/pwntools

```
sudo apt-get update
sudo apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
```

