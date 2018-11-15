import dns, dns.rcode, dns.zone
import socket
import struct
import sys
import threading

class AXFRServer(object):

    def __init__(self, port, zones):
        self._currentSerial = 0
        self._servedSerial = 0
        self._serverPort = port
        self._zones = zones
        listener = threading.Thread(name='AXFR Listener', target=self._listener, args=[])
        listener.setDaemon(True)
        listener.start()
        udplistener = threading.Thread(name='AXFR udplistener', target=self._udplistener, args=[])
        udplistener.setDaemon(True)
        udplistener.start()

    def _getRecordsForSerial(self, serial):
        ret = []
        for i in dns.zone.from_text(self._zones[serial], relativize=False).iterate_rdatasets():
            n, rds = i
            rrs=dns.rrset.RRset(n, rds.rdclass, rds.rdtype)
            rrs.update(rds)
            ret.append(rrs)

        # now stick a SOA at the end
        ret.append(ret[0])
        return ret

    def _getSOAForSerial(self, serial):
        return self._getRecordsForSerial(serial)[0]

    def getCurrentSerial(self):
        return self._currentSerial

    def getServedSerial(self):
        return self._servedSerial

    def moveToSerial(self, newSerial):
        print("current serial is %d, moving to %d" % (self._currentSerial, newSerial))
        if newSerial == self._currentSerial:
            return False

        if newSerial != self._currentSerial + 1:
            raise AssertionError("Asking the AXFR server to serve serial %d, already serving %d" % (newSerial, self._currentSerial))

        if newSerial not in self._zones:
            raise AssertionError("Asking the AXFR server to serve serial %d, but we don't have a corresponding zone" % (newSerial))

        self._currentSerial = newSerial
        return True

    def _getAnswer(self, message):

        response = dns.message.make_response(message)
        records = []

        if (message.question[0].rdtype == dns.rdatatype.AXFR) or \
           (message.question[0].rdtype == dns.rdatatype.IXFR and message.authority[0].items[0].serial < self._currentSerial):
            records = self._getRecordsForSerial(self._currentSerial)
        else:
            # IXFR request for current version of zone
            records = [self._getSOAForSerial(self._currentSerial)]

        response.answer = records
        return (self._currentSerial, response)

    def _connectionHandler(self, conn):
        data = None
        while True:
            data = conn.recv(2)
            if not data:
                break
            (datalen,) = struct.unpack("!H", data)
            data = conn.recv(datalen)
            if not data:
                break

            message = dns.message.from_wire(data)
            if len(message.question) != 1:
                print('Invalid AXFR query, qdcount is %d' % (len(message.question)))
                break
            if not message.question[0].rdtype in [dns.rdatatype.AXFR, dns.rdatatype.IXFR]:
                print('Invalid AXFR query, qtype is %d' % (message.question[0].rdtype))
                break
            (serial, answer) = self._getAnswer(message)
            if not answer:
                print('Unable to get a response for %s %d' % (message.question[0].name, message.question[0].rdtype))
                break

            wire = answer.to_wire()
            conn.send(struct.pack("!H", len(wire)))
            conn.send(wire)
            self._servedSerial = serial
            break

        conn.close()

    def _listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            sock.bind(("127.0.0.1", self._serverPort))
        except socket.error as e:
            print("Error binding in the AXFR listener: %s" % str(e))
            sys.exit(1)

        sock.listen(100)
        while True:
            try:
                (conn, _) = sock.accept()
                thread = threading.Thread(name='AXFR Connection Handler',
                                      target=self._connectionHandler,
                                      args=[conn])
                thread.setDaemon(True)
                thread.start()

            except socket.error as e:
                print('Error in AXFR socket: %s' % str(e))
                sock.close()

    def _udplistener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("127.0.0.1", self._serverPort))
        except socket.error as e:
            print("Error binding in the UDP AXFR listener: %s" % str(e))
            sys.exit(1)

        while True:
            data, addr = sock.recvfrom(512)
            message = dns.message.from_wire(data)
            if len(message.question) != 1:
                print('Invalid UDP query, qdcount is %d' % (len(message.question)))
                break
            if not message.question[0].rdtype in [dns.rdatatype.SOA]:
                print('Invalid UDP query, qtype is %d' % (message.question.rdtype))
                break

            response = dns.message.make_response(message)

            if self._currentSerial in self._zones:
                response.answer = [self._getSOAForSerial(self._currentSerial)]
            else:
                response.set_rcode(dns.rcode.REFUSED)

            wire = response.to_wire()
            sock.sendto(wire, addr)
