require('zmq')

ctx = zmq:ctx_new()
s = ctx:socket(zmq.REP)

print(s:bind('tcp://*:5555'))

print(s:recv())

print(s:send('world'))

s:close()
ctx:term()