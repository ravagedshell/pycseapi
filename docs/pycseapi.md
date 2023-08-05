# Secure Endpoint API Toolkit (pycseapi.py)
Easily perform programmatic management of your Secure Endpoint organizations with some simple python functions.

## get_organizations ()
Get's a list of organizations you're a member of.

### Syntax
`get_organizations( limit, start )`

#### Variables
* limit - An integer value defining how many organizations to retreive
* start - An integer value defining where to start if you're over the paginiation limit

### Example
```python
print( get_organizations( 10, 0 )
```

## move_computer()
This function moves a connector from one group to another.

### Syntax
`move_computer( computer_guid, group_guid )`

#### Variables
* computer_guid - The connectors unique identifier that you want to move
* group_guid - The unique ID of the group you want to move this connector to

### Example
```python
if( move_computer( "uniquecomputerid", "uniquegroupid" ) ):
    print ( "We moved da computa! Good job bossman" )
else:
    print ( "Woops, Linus must of dropped it on his way through the Internet Exchange" )
```