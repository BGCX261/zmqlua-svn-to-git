require('zmq')

ctx = zmq:ctx_new()
s = ctx:socket(zmq.REQ)

s:connect('tcp://localhost:5555')

print(s:send('hello'))

print(s:recv())

s:close()
ctx:term()