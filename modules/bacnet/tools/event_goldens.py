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

# ---- second half: event values of the other algorithms, Event_Parameters, LifeSafetyOperation
from bacpypes3.pdu import PDUData
def enc(obj):
    a = Any(obj)
    out=b''
    for t in a.tagList:
        d = PDUData(); t.encode(d) if False else None
        out += t.encode().pduData if hasattr(t.encode(),'pduData') else bytes(t.encode())
    return out.hex()
sf = StatusFlags([1,0,0,0])
np = NotificationParameters(changeOfState=NotificationParametersChangeOfState(newState=PropertyStates(binaryValue=BinaryPV("active")), statusFlags=sf))
print(enc(np))
print("--- notification parameters")
np = NotificationParameters
def P(label, v): print(label, enc(v))
P("cobits", np(changeOfBitstring=NotificationParametersChangeOfBitstring(referencedBitstring=BitString([1,0,1,1,0]), statusFlags=sf)))
P("cov-bits", np(changeOfValue=NotificationParametersChangeOfValue(newValue=NotificationParametersChangeOfValueNewValue(changedBits=BitString([0,1,1])), statusFlags=sf)))
P("cov-real", np(changeOfValue=NotificationParametersChangeOfValue(newValue=NotificationParametersChangeOfValueNewValue(changedValue=12.5), statusFlags=sf)))
P("cmdfail", np(commandFailure=NotificationParametersCommandFailure(commandValue=Any(Enumerated(1)), statusFlags=sf, feedbackValue=Any(Enumerated(0)))))
P("float", np(floatingLimit=NotificationParametersFloatingLimit(referenceValue=71.5, statusFlags=sf, setpointValue=70.0, errorLimit=1.0)))
P("urange", np(unsignedRange=NotificationParametersUnsignedRange(exceedingValue=1500, statusFlags=sf, exceedingLimit=1000)))
P("reliab", np(changeOfReliability=NotificationParametersChangeOfReliabilityType(reliability=Reliability("over-range"), statusFlags=StatusFlags([1,1,0,0]), propertyValues=[])))
P("cols", np(changeOfLifeSafety=NotificationParametersChangeOfLifeSafety(newState=LifeSafetyState("alarm"), newMode=LifeSafetyMode("on"), statusFlags=sf, operationExpected=LifeSafetyOperation("silence"))))
print("--- event parameters")
E = EventParameter
P("ep-bits", E(changeOfBitstring=EventParameterChangeOfBitstring(timeDelay=5, bitmask=BitString([1,1,0,0]), listOfBitstringValues=[BitString([1,0,0,0]), BitString([0,1,0,0])])))
P("ep-state", E(changeOfState=EventParameterChangeOfState(timeDelay=5, listOfValues=[PropertyStates(binaryValue=BinaryPV("active")), PropertyStates(unsignedValue=3)])))
P("ep-cov-incr", E(changeOfValue=EventParameterChangeOfValue(timeDelay=5, covCriteria=EventParameterChangeOfValueCOVCriteria(referencedPropertyIncrement=0.5))))
P("ep-cov-mask", E(changeOfValue=EventParameterChangeOfValue(timeDelay=5, covCriteria=EventParameterChangeOfValueCOVCriteria(bitmask=BitString([1,1,1])))))
ref = DeviceObjectPropertyReference(objectIdentifier=ObjectIdentifier("analog-input,5"), propertyIdentifier=PropertyIdentifier("present-value"))
P("dopr", ref)
P("dopr-full", DeviceObjectPropertyReference(objectIdentifier=ObjectIdentifier("multi-state-value,5"), propertyIdentifier=PropertyIdentifier("present-value"), propertyArrayIndex=3, deviceIdentifier=ObjectIdentifier("device,599")))
P("ep-cmdfail", E(commandFailure=EventParameterCommandFailure(timeDelay=5, feedbackPropertyReference=ref)))
P("ep-float", E(floatingLimit=EventParameterFloatingLimit(timeDelay=5, setpointReference=ref, lowDiffLimit=1.5, highDiffLimit=2.5, deadband=0.5)))
P("ep-oor", E(outOfRange=EventParameterOutOfRange(timeDelay=5, lowLimit=10.0, highLimit=90.0, deadband=2.0)))
P("ep-urange", E(unsignedRange=EventParameterUnsignedRange(timeDelay=5, lowLimit=10, highLimit=90)))
P("ep-none", E(none=Null(())))
print("--- life safety operation")
print(LifeSafetyOperationRequest(requestingProcessIdentifier=7, requestingSource=CharacterString("op"), request=LifeSafetyOperation("silence"), objectIdentifier=ObjectIdentifier("life-safety-point,3")).encode().pduData.hex())
print(LifeSafetyOperationRequest(requestingProcessIdentifier=7, requestingSource=CharacterString("op"), request=LifeSafetyOperation("reset-alarm")).encode().pduData.hex())
print(list(LifeSafetyOperation.__dict__.get('_enum_map', {}).items()) if hasattr(LifeSafetyOperation,'_enum_map') else dir(LifeSafetyOperation)[:5])

print("--- change of reliability with property values")
from bacpypes3.basetypes import PropertyValue
P("reliab-pv", np(changeOfReliability=NotificationParametersChangeOfReliabilityType(reliability=Reliability("monitored-object-fault"), statusFlags=StatusFlags([1,1,0,0]), propertyValues=[PropertyValue(propertyIdentifier=PropertyIdentifier("present-value"), value=Any(Real(95.0))), PropertyValue(propertyIdentifier=PropertyIdentifier("reliability"), value=Any(Enumerated(14)))])))
