# Recipe for the event-service goldens in src/events.zig: bacpypes3 0.0.106 (black box).
# Run: python3 event_goldens.py  (prints service-body hex).
from bacpypes3.apdu import *
from bacpypes3.primitivedata import *
from bacpypes3.basetypes import *
from bacpypes3.constructeddata import *
from bacpypes3.pdu import Address
import sys
def hx(pdu):
    return pdu.encode().pduData.hex()
ts = TimeStamp(sequenceNumber=5)
n = UnconfirmedEventNotificationRequest(
    processIdentifier=7,
    initiatingDeviceIdentifier=ObjectIdentifier("device,599"),
    eventObjectIdentifier=ObjectIdentifier("analog-input,5"),
    timeStamp=ts,
    notificationClass=3,
    priority=100,
    eventType=EventType("out-of-range"),
    messageText=CharacterString("hot"),
    notifyType=NotifyType("alarm"),
    ackRequired=True,
    fromState=EventState("normal"),
    toState=EventState("high-limit"),
    eventValues=NotificationParameters(outOfRange=NotificationParametersOutOfRange(exceedingValue=91.5,statusFlags=StatusFlags([1,0,0,0]),deadband=2.0,exceededLimit=90.0)),
)
print(hx(n))
print("--- ack alarm")
a = AcknowledgeAlarmRequest(acknowledgingProcessIdentifier=7, eventObjectIdentifier=ObjectIdentifier("analog-input,5"), eventStateAcknowledged=EventState("high-limit"), timeStamp=TimeStamp(sequenceNumber=5), acknowledgmentSource=CharacterString("op"), timeOfAcknowledgment=TimeStamp(sequenceNumber=6))
print(hx(a))
print("--- gei req")
print(hx(GetEventInformationRequest(lastReceivedObjectIdentifier=ObjectIdentifier("analog-input,5"))))
print(hx(GetEventInformationRequest()))
print("--- gei ack")
from bacpypes3.basetypes import GetEventInformationEventSummary as EventSummary, EventTransitionBits, GetAlarmSummaryAlarmSummary
es = EventSummary(objectIdentifier=ObjectIdentifier("analog-input,5"), eventState=EventState("high-limit"), acknowledgedTransitions=EventTransitionBits([0,1,1]), eventTimeStamps=SequenceOf(TimeStamp)([TimeStamp(sequenceNumber=5),TimeStamp(time=Time("1.2.3.4")) if False else TimeStamp(sequenceNumber=0),TimeStamp(sequenceNumber=9)]), notifyType=NotifyType("alarm"), eventEnable=EventTransitionBits([1,0,1]), eventPriorities=SequenceOf(Unsigned)([100,100,200]))
g = GetEventInformationACK(listOfEventSummaries=[es], moreEvents=True)
print(hx(g))
print("--- alarm summary ack")
GA = GetAlarmSummaryACK(listOfAlarmSummaries=[GetAlarmSummaryAlarmSummary(objectIdentifier=ObjectIdentifier("analog-input,5"), alarmState=EventState("high-limit"), acknowledgedTransitions=EventTransitionBits([0,1,1]))])
print(hx(GA))
