require('zmq')

ctx = zmq:ctx_new()
s = ctx:socket(zmq.PUB)

s:bind('tcp://*:5555')

while true do
	s:send('hello world')
	zmq.sleep(1)
end

s:close()
ctx:term()