require('zmq')

ctx = zmq:ctx_new()
s = ctx:socket(zmq.SUB)

s:connect('tcp://localhost:5555')
s:setsockopt(zmq.SUBSCRIBE, '')

while true do
	print(s:recv())
end

s:close()
ctx:term()