// SPDX-License-Identifier: MIT

//! The BACnet enumeration vocabulary (ASHRAE 135 clauses 12, 21 and Annex E):
//! object types, property identifiers, the error class/code pairs an `Error`
//! PDU carries, and the reject/abort reasons.
//!
//! Every enum here is **non-exhaustive** (`_`). BACnet reserves whole ranges
//! for vendors (object types >= 128, property identifiers >= 512, error codes
//! >= 256), so a decoder that refuses an unnamed value is wrong — an unknown
//! enumeration must survive a round trip with its numeric value intact. The
//! named members are the ones a building-automation client actually meets.

const std = @import("std");

/// Object types (clause 21, `BACnetObjectType`). Values 0..127 are reserved by
/// ASHRAE; 128..1023 are vendor-proprietary. An `ObjectIdentifier` packs one of
/// these into its top 10 bits.
pub const ObjectType = enum(u10) {
    analog_input = 0,
    analog_output = 1,
    analog_value = 2,
    binary_input = 3,
    binary_output = 4,
    binary_value = 5,
    calendar = 6,
    command = 7,
    device = 8,
    event_enrollment = 9,
    file = 10,
    group = 11,
    loop = 12,
    multi_state_input = 13,
    multi_state_output = 14,
    notification_class = 15,
    program = 16,
    schedule = 17,
    averaging = 18,
    multi_state_value = 19,
    trend_log = 20,
    life_safety_point = 21,
    life_safety_zone = 22,
    accumulator = 23,
    pulse_converter = 24,
    event_log = 25,
    global_group = 26,
    trend_log_multiple = 27,
    load_control = 28,
    structured_view = 29,
    access_door = 30,
    timer = 31,
    access_credential = 32,
    access_point = 33,
    access_rights = 34,
    access_user = 35,
    access_zone = 36,
    credential_data_input = 37,
    network_security = 38,
    bitstring_value = 39,
    characterstring_value = 40,
    date_pattern_value = 41,
    date_value = 42,
    datetime_pattern_value = 43,
    datetime_value = 44,
    integer_value = 45,
    large_analog_value = 46,
    octetstring_value = 47,
    positive_integer_value = 48,
    time_pattern_value = 49,
    time_value = 50,
    notification_forwarder = 51,
    alert_enrollment = 52,
    channel = 53,
    lighting_output = 54,
    binary_lighting_output = 55,
    network_port = 56,
    elevator_group = 57,
    escalator = 58,
    lift = 59,
    staging = 60,
    audit_log = 61,
    audit_reporter = 62,
    color = 63,
    color_temperature = 64,
    _,

    /// True for the vendor-proprietary range (>= 128). The standard reserves
    /// 0..127 for itself, so an unnamed value below 128 is a *future* standard
    /// type, not a vendor one.
    pub fn isProprietary(self: ObjectType) bool {
        return @intFromEnum(self) >= 128;
    }
};

/// Property identifiers (clause 21, `BACnetPropertyIdentifier`). Values 0..511
/// are reserved by ASHRAE; 512.. are vendor-proprietary. The three
/// **special** identifiers `all`/`required`/`optional` are only legal inside a
/// ReadPropertyMultiple request (clause 15.7) — never as a real property.
pub const PropertyIdentifier = enum(u32) {
    acked_transitions = 0,
    ack_required = 1,
    action = 2,
    action_text = 3,
    active_text = 4,
    active_vt_sessions = 5,
    alarm_value = 6,
    alarm_values = 7,
    all = 8,
    all_writes_successful = 9,
    apdu_segment_timeout = 10,
    apdu_timeout = 11,
    application_software_version = 12,
    archive = 13,
    bias = 14,
    change_of_state_count = 15,
    change_of_state_time = 16,
    notification_class = 17,
    controlled_variable_reference = 19,
    controlled_variable_units = 20,
    controlled_variable_value = 21,
    cov_increment = 22,
    datelist = 23,
    daylight_savings_status = 24,
    deadband = 25,
    derivative_constant = 26,
    derivative_constant_units = 27,
    description = 28,
    description_of_halt = 29,
    device_address_binding = 30,
    device_type = 31,
    effective_period = 32,
    elapsed_active_time = 33,
    error_limit = 34,
    event_enable = 35,
    event_state = 36,
    event_type = 37,
    exception_schedule = 38,
    fault_values = 39,
    feedback_value = 40,
    file_access_method = 41,
    file_size = 42,
    file_type = 43,
    firmware_revision = 44,
    high_limit = 45,
    inactive_text = 46,
    in_process = 47,
    instance_of = 48,
    integral_constant = 49,
    integral_constant_units = 50,
    limit_enable = 52,
    list_of_group_members = 53,
    list_of_object_property_references = 54,
    local_date = 56,
    local_time = 57,
    location = 58,
    low_limit = 59,
    manipulated_variable_reference = 60,
    maximum_output = 61,
    max_apdu_length_accepted = 62,
    max_info_frames = 63,
    max_master = 64,
    max_pres_value = 65,
    minimum_off_time = 66,
    minimum_on_time = 67,
    minimum_output = 68,
    min_pres_value = 69,
    model_name = 70,
    modification_date = 71,
    notify_type = 72,
    number_of_apdu_retries = 73,
    number_of_states = 74,
    object_identifier = 75,
    object_list = 76,
    object_name = 77,
    object_property_reference = 78,
    object_type = 79,
    optional = 80,
    out_of_service = 81,
    output_units = 82,
    event_parameters = 83,
    polarity = 84,
    present_value = 85,
    priority = 86,
    priority_array = 87,
    priority_for_writing = 88,
    process_identifier = 89,
    program_change = 90,
    program_location = 91,
    program_state = 92,
    proportional_constant = 93,
    proportional_constant_units = 94,
    protocol_object_types_supported = 96,
    protocol_services_supported = 97,
    protocol_version = 98,
    read_only = 99,
    reason_for_halt = 100,
    recipient_list = 102,
    reliability = 103,
    relinquish_default = 104,
    required = 105,
    resolution = 106,
    segmentation_supported = 107,
    setpoint = 108,
    setpoint_reference = 109,
    state_text = 110,
    status_flags = 111,
    system_status = 112,
    time_delay = 113,
    time_of_active_time_reset = 114,
    time_of_state_count_reset = 115,
    time_synchronization_recipients = 116,
    units = 117,
    update_interval = 118,
    utc_offset = 119,
    vendor_identifier = 120,
    vendor_name = 121,
    vt_classes_supported = 122,
    weekly_schedule = 123,
    attempted_samples = 124,
    average_value = 125,
    buffer_size = 126,
    client_cov_increment = 127,
    cov_resubscription_interval = 128,
    event_time_stamps = 130,
    log_buffer = 131,
    log_device_object_property = 132,
    enable = 133,
    log_interval = 134,
    maximum_value = 135,
    minimum_value = 136,
    notification_threshold = 137,
    protocol_revision = 139,
    records_since_notification = 140,
    record_count = 141,
    start_time = 142,
    stop_time = 143,
    stop_when_full = 144,
    total_record_count = 145,
    valid_samples = 146,
    window_interval = 147,
    window_samples = 148,
    maximum_value_timestamp = 149,
    minimum_value_timestamp = 150,
    variance_value = 151,
    active_cov_subscriptions = 152,
    backup_failure_timeout = 153,
    configuration_files = 154,
    database_revision = 155,
    direct_reading = 156,
    last_restore_time = 157,
    maintenance_required = 158,
    member_of = 159,
    mode = 160,
    operation_expected = 161,
    setting = 162,
    silenced = 163,
    tracking_value = 164,
    zone_members = 165,
    life_safety_alarm_values = 166,
    max_segments_accepted = 167,
    profile_name = 168,
    auto_slave_discovery = 169,
    manual_slave_address_binding = 170,
    slave_address_binding = 171,
    slave_proxy_enable = 172,
    last_notify_record = 173,
    schedule_default = 174,
    accepted_modes = 175,
    adjust_value = 176,
    count = 177,
    count_before_change = 178,
    count_change_time = 179,
    cov_period = 180,
    input_reference = 181,
    limit_monitoring_interval = 182,
    logging_object = 183,
    logging_record = 184,
    prescale = 185,
    pulse_rate = 186,
    scale = 187,
    scale_factor = 188,
    update_time = 189,
    value_before_change = 190,
    value_set = 191,
    value_change_time = 192,
    align_intervals = 193,
    interval_offset = 195,
    last_restart_reason = 196,
    logging_type = 197,
    restart_notification_recipients = 202,
    time_of_device_restart = 203,
    time_synchronization_interval = 204,
    trigger = 205,
    utc_time_synchronization_recipients = 206,
    node_subtype = 207,
    node_type = 208,
    structured_object_list = 209,
    subordinate_annotations = 210,
    subordinate_list = 211,
    event_message_texts = 232,
    event_message_texts_config = 233,
    event_detection_enable = 353,
    event_algorithm_inhibit = 354,
    event_algorithm_inhibit_ref = 355,
    time_delay_normal = 356,
    reliability_evaluation_inhibit = 357,
    fault_parameters = 358,
    fault_type = 359,
    local_forwarding_only = 360,
    process_identifier_filter = 361,
    subscribed_recipients = 362,
    port_filter = 363,
    _,

    /// The three ReadPropertyMultiple wildcards (clause 15.7.1.2). They are
    /// only meaningful in a property reference inside an RPM request.
    pub fn isSpecial(self: PropertyIdentifier) bool {
        return switch (self) {
            .all, .required, .optional => true,
            else => false,
        };
    }

    pub fn isProprietary(self: PropertyIdentifier) bool {
        return @intFromEnum(self) >= 512;
    }
};

/// Confirmed service choices (clause 21, `BACnetConfirmedServiceChoice`).
pub const ConfirmedService = enum(u8) {
    acknowledge_alarm = 0,
    confirmed_cov_notification = 1,
    confirmed_event_notification = 2,
    get_alarm_summary = 3,
    get_enrollment_summary = 4,
    subscribe_cov = 5,
    atomic_read_file = 6,
    atomic_write_file = 7,
    add_list_element = 8,
    remove_list_element = 9,
    create_object = 10,
    delete_object = 11,
    read_property = 12,
    read_property_conditional = 13,
    read_property_multiple = 14,
    write_property = 15,
    write_property_multiple = 16,
    device_communication_control = 17,
    confirmed_private_transfer = 18,
    confirmed_text_message = 19,
    reinitialize_device = 20,
    vt_open = 21,
    vt_close = 22,
    vt_data = 23,
    authenticate = 24,
    request_key = 25,
    read_range = 26,
    life_safety_operation = 27,
    subscribe_cov_property = 28,
    get_event_information = 29,
    subscribe_cov_property_multiple = 30,
    confirmed_cov_notification_multiple = 31,
    confirmed_audit_notification = 32,
    audit_log_query = 33,
    _,
};

/// Unconfirmed service choices (clause 21, `BACnetUnconfirmedServiceChoice`).
pub const UnconfirmedService = enum(u8) {
    i_am = 0,
    i_have = 1,
    unconfirmed_cov_notification = 2,
    unconfirmed_event_notification = 3,
    unconfirmed_private_transfer = 4,
    unconfirmed_text_message = 5,
    time_synchronization = 6,
    who_has = 7,
    who_is = 8,
    utc_time_synchronization = 9,
    write_group = 10,
    unconfirmed_cov_notification_multiple = 11,
    unconfirmed_audit_notification = 12,
    who_am_i = 13,
    you_are = 14,
    _,
};

/// Error class (clause 18, `BACnetErrorClass`).
pub const ErrorClass = enum(u16) {
    device = 0,
    object = 1,
    property = 2,
    resources = 3,
    security = 4,
    services = 5,
    vt = 6,
    communication = 7,
    _,
};

/// Error code (clause 18, `BACnetErrorCode`). Only the codes a property
/// read/write realistically returns are named; the rest survive numerically.
pub const ErrorCode = enum(u16) {
    other = 0,
    authentication_failed = 1,
    configuration_in_progress = 2,
    device_busy = 3,
    dynamic_creation_not_supported = 4,
    file_access_denied = 5,
    incompatible_security_levels = 6,
    inconsistent_parameters = 7,
    inconsistent_selection_criterion = 8,
    invalid_data_type = 9,
    invalid_file_access_method = 10,
    invalid_file_start_position = 11,
    invalid_operator_name = 12,
    invalid_parameter_data_type = 13,
    invalid_time_stamp = 14,
    key_generation_error = 15,
    missing_required_parameter = 16,
    no_objects_of_specified_type = 17,
    no_space_for_object = 18,
    no_space_to_add_list_element = 19,
    no_space_to_write_property = 20,
    no_vt_sessions_available = 21,
    property_is_not_a_list = 22,
    object_deletion_not_permitted = 23,
    object_identifier_already_exists = 24,
    operational_problem = 25,
    password_failure = 26,
    read_access_denied = 27,
    security_not_supported = 28,
    service_request_denied = 29,
    timeout = 30,
    unknown_object = 31,
    unknown_property = 32,
    unknown_vt_class = 34,
    unknown_vt_session = 35,
    unsupported_object_type = 36,
    value_out_of_range = 37,
    vt_session_already_closed = 38,
    vt_session_termination_failure = 39,
    write_access_denied = 40,
    character_set_not_supported = 41,
    invalid_array_index = 42,
    cov_subscription_failed = 43,
    not_cov_property = 44,
    optional_functionality_not_supported = 45,
    invalid_configuration_data = 46,
    datatype_not_supported = 47,
    duplicate_name = 48,
    duplicate_object_id = 49,
    property_is_not_an_array = 50,
    abort_buffer_overflow = 51,
    abort_invalid_apdu_in_this_state = 52,
    abort_preempted_by_higher_priority_task = 53,
    abort_segmentation_not_supported = 54,
    abort_proprietary = 55,
    abort_other = 56,
    invalid_tag = 57,
    network_down = 58,
    reject_buffer_overflow = 59,
    reject_inconsistent_parameters = 60,
    reject_invalid_parameter_data_type = 61,
    reject_invalid_tag = 62,
    reject_missing_required_parameter = 63,
    reject_parameter_out_of_range = 64,
    reject_too_many_arguments = 65,
    reject_undefined_enumeration = 66,
    reject_unrecognized_service = 67,
    reject_proprietary = 68,
    reject_other = 69,
    unknown_device = 70,
    unknown_route = 71,
    value_not_initialized = 72,
    invalid_event_state = 73,
    no_alarm_configured = 74,
    log_buffer_full = 75,
    logged_value_purged = 76,
    no_property_specified = 77,
    not_configured_for_triggered_logging = 78,
    unknown_subscription = 79,
    parameter_out_of_range = 80,
    list_element_not_found = 81,
    busy = 82,
    communication_disabled = 83,
    success = 84,
    access_denied = 85,
    bad_destination_address = 86,
    _,
};

/// Reject reasons (clause 18.8, `BACnetRejectReason`). A Reject PDU says the
/// request could not even be *interpreted*.
pub const RejectReason = enum(u8) {
    other = 0,
    buffer_overflow = 1,
    inconsistent_parameters = 2,
    invalid_parameter_data_type = 3,
    invalid_tag = 4,
    missing_required_parameter = 5,
    parameter_out_of_range = 6,
    too_many_arguments = 7,
    undefined_enumeration = 8,
    unrecognized_service = 9,
    _,
};

/// Abort reasons (clause 18.9, `BACnetAbortReason`). An Abort PDU tears the
/// whole transaction down. `segmentation_not_supported` is the one this module
/// emits when a peer offers a segmented request it will not reassemble.
pub const AbortReason = enum(u8) {
    other = 0,
    buffer_overflow = 1,
    invalid_apdu_in_this_state = 2,
    preempted_by_higher_priority_task = 3,
    segmentation_not_supported = 4,
    security_error = 5,
    insufficient_security = 6,
    out_of_resources = 7,
    tsm_timeout = 8,
    apdu_too_long = 9,
    _,
};

/// `BACnetSegmentation` (clause 21) — what a device advertises in its Device
/// object's `segmentation_supported` property.
pub const Segmentation = enum(u8) {
    both = 0,
    transmit = 1,
    receive = 2,
    none = 3,
    _,
};

/// `BACnetDeviceStatus` (clause 21).
pub const DeviceStatus = enum(u16) {
    operational = 0,
    operational_read_only = 1,
    download_required = 2,
    download_in_progress = 3,
    non_operational = 4,
    backup_in_progress = 5,
    _,
};

/// `BACnetBinaryPV` (clause 21) — the present value of a binary object.
pub const BinaryPV = enum(u32) {
    inactive = 0,
    active = 1,
    _,
};

/// `BACnetEventState` (clause 21).
pub const EventState = enum(u32) {
    normal = 0,
    fault = 1,
    offnormal = 2,
    high_limit = 3,
    low_limit = 4,
    life_safety_alarm = 5,
    _,
};

/// `BACnetReliability` (clause 21).
pub const Reliability = enum(u32) {
    no_fault_detected = 0,
    no_sensor = 1,
    over_range = 2,
    under_range = 3,
    open_loop = 4,
    shorted_loop = 5,
    no_output = 6,
    unreliable_other = 7,
    process_error = 8,
    multi_state_fault = 9,
    configuration_error = 10,
    communication_failure = 12,
    member_fault = 13,
    monitored_object_fault = 14,
    tripped = 15,
    lamp_failure = 16,
    activation_failure = 17,
    renew_dhcp_failure = 18,
    renew_fd_registration_failure = 19,
    restart_auto_negotiation_failure = 20,
    restart_failure = 21,
    proprietary_command_failure = 22,
    faults_listed = 23,
    referenced_object_fault = 24,
    _,
};

/// `BACnetEngineeringUnits` (clause 21, Annex E) — the common subset. The full
/// table has several hundred entries; unnamed values still round-trip.
pub const EngineeringUnits = enum(u32) {
    square_meters = 0,
    square_feet = 1,
    milliamperes = 2,
    amperes = 3,
    ohms = 4,
    volts = 5,
    kilovolts = 6,
    megavolts = 7,
    volt_amperes = 8,
    kilovolt_amperes = 9,
    watts = 47,
    kilowatts = 48,
    megawatts = 49,
    degrees_celsius = 62,
    degrees_kelvin = 63,
    degrees_fahrenheit = 64,
    percent = 98,
    percent_relative_humidity = 29,
    pascals = 53,
    kilopascals = 54,
    bars = 55,
    no_units = 95,
    parts_per_million = 96,
    seconds = 73,
    minutes = 72,
    hours = 71,
    days = 70,
    cubic_meters_per_hour = 135,
    liters_per_second = 87,
    cubic_feet_per_minute = 84,
    hertz = 27,
    _,
};

/// `BACnetStatusFlags` (clause 21) — a four-bit BitString every present-value
/// carrying object exposes. Bit order on the wire is MSB-first from bit 0.
pub const StatusFlags = packed struct {
    in_alarm: bool = false,
    fault: bool = false,
    overridden: bool = false,
    out_of_service: bool = false,

    /// The four bits packed MSB-first into one octet, which is exactly the
    /// BitString data octet (with an unused-bit count of 4).
    pub fn toOctet(self: StatusFlags) u8 {
        var b: u8 = 0;
        if (self.in_alarm) b |= 0x80;
        if (self.fault) b |= 0x40;
        if (self.overridden) b |= 0x20;
        if (self.out_of_service) b |= 0x10;
        return b;
    }

    pub fn fromOctet(b: u8) StatusFlags {
        return .{
            .in_alarm = (b & 0x80) != 0,
            .fault = (b & 0x40) != 0,
            .overridden = (b & 0x20) != 0,
            .out_of_service = (b & 0x10) != 0,
        };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "enums are non-exhaustive: an unnamed value round-trips" {
    // A vendor object type nobody has heard of must survive decode/encode.
    const vendor: ObjectType = @enumFromInt(600);
    try testing.expectEqual(@as(u10, 600), @intFromEnum(vendor));
    try testing.expect(vendor.isProprietary());

    const vendor_prop: PropertyIdentifier = @enumFromInt(4194000);
    try testing.expect(vendor_prop.isProprietary());

    // ... but an unnamed value below the vendor line is a *future standard*
    // one, not a proprietary one.
    const future: ObjectType = @enumFromInt(100);
    try testing.expect(!future.isProprietary());
}

test "ReadPropertyMultiple wildcards" {
    try testing.expect(PropertyIdentifier.all.isSpecial());
    try testing.expect(PropertyIdentifier.required.isSpecial());
    try testing.expect(PropertyIdentifier.optional.isSpecial());
    try testing.expect(!PropertyIdentifier.present_value.isSpecial());
    try testing.expectEqual(@as(u32, 8), @intFromEnum(PropertyIdentifier.all));
    try testing.expectEqual(@as(u32, 80), @intFromEnum(PropertyIdentifier.optional));
    try testing.expectEqual(@as(u32, 105), @intFromEnum(PropertyIdentifier.required));
}

test "status flags pack MSB-first" {
    try testing.expectEqual(@as(u8, 0x00), (StatusFlags{}).toOctet());
    try testing.expectEqual(@as(u8, 0x80), (StatusFlags{ .in_alarm = true }).toOctet());
    try testing.expectEqual(@as(u8, 0x10), (StatusFlags{ .out_of_service = true }).toOctet());
    try testing.expectEqual(@as(u8, 0xF0), (StatusFlags{
        .in_alarm = true,
        .fault = true,
        .overridden = true,
        .out_of_service = true,
    }).toOctet());
    const rt = StatusFlags.fromOctet(0x90);
    try testing.expect(rt.in_alarm and !rt.fault and !rt.overridden and rt.out_of_service);
}

test "well-known numeric values match the standard's tables" {
    try testing.expectEqual(@as(u10, 8), @intFromEnum(ObjectType.device));
    try testing.expectEqual(@as(u10, 0), @intFromEnum(ObjectType.analog_input));
    try testing.expectEqual(@as(u10, 20), @intFromEnum(ObjectType.trend_log));
    try testing.expectEqual(@as(u32, 85), @intFromEnum(PropertyIdentifier.present_value));
    try testing.expectEqual(@as(u32, 87), @intFromEnum(PropertyIdentifier.priority_array));
    try testing.expectEqual(@as(u32, 77), @intFromEnum(PropertyIdentifier.object_name));
    try testing.expectEqual(@as(u8, 12), @intFromEnum(ConfirmedService.read_property));
    try testing.expectEqual(@as(u8, 14), @intFromEnum(ConfirmedService.read_property_multiple));
    try testing.expectEqual(@as(u8, 15), @intFromEnum(ConfirmedService.write_property));
    try testing.expectEqual(@as(u8, 8), @intFromEnum(UnconfirmedService.who_is));
    try testing.expectEqual(@as(u8, 0), @intFromEnum(UnconfirmedService.i_am));
    try testing.expectEqual(@as(u8, 4), @intFromEnum(AbortReason.segmentation_not_supported));
}
