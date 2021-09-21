////////////////////////////////////////////////////////////////////////////////////
//
// SamplesLoader loads probe sample data from binary files
//
// Xpedite probes store timing and performance counter data using variable 
// length POD objects. A collection of sample objects is grouped and written
// as a batch. 
//
// The loader iterates through the POD collection,  to extract 
// records in string format for consumption by the profiler
//
// Author: Manikandan Dhamodharan, Morgan Stanley
//
////////////////////////////////////////////////////////////////////////////////////

#include <xpedite/framework/SamplesLoader.H>
#include <iostream>
#include <iomanip>
#include <ios>
#include <chrono>
using namespace xpedite::probes;
using namespace xpedite::framework;

std::chrono::nanoseconds first_sample_ns(1630501200000000000LL);
using ClockTicks = std::chrono::duration<double, std::ratio<1, 2494429297LL>>;

std::chrono::nanoseconds _clock_ticks_to_nanoseconds(ClockTicks first_sample_tsc, ClockTicks tsc) {
     return first_sample_ns + std::chrono::duration_cast<std::chrono::nanoseconds>(tsc-first_sample_tsc);
}


#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <babeltrace2/babeltrace.h>

/* Source component's private data */
struct xpedite_in {
    int32_t tid; // thread ID for the stream
    /* Stream (owned by this) */
    bt_stream *stream;
    SamplesLoader *loader;
};

typedef enum IterState {
     ITER_STATE_BEGIN_STREAM,
     ITER_STATE_APPEND_SAMPLES,
} IterState_t;

struct xpedite_iter {
     IterState_t state;
     bt_packet *packet;
     uint64_t packet_roll_timestamp;
     SamplesLoader::Iterator samples;
     ClockTicks first_sample_tsc;
};

/*
 * Creates an event class within `stream_class` for the provided `probe`.
 */
void create_event_class(bt_stream_class *stream_class, ProbeInfo *probe)
{
     #if 0
    /* Borrow trace class from stream class */
    bt_trace_class *trace_class =
        bt_stream_class_borrow_trace_class(stream_class);
    #endif

    /* Create a default event class */
    bt_event_class *event_class = bt_event_class_create_with_id(stream_class, (uint64_t)probe->recorder_return_site);

    /* Name the event class */
    bt_event_class_set_name(event_class, probe->name.c_str());

    #if 0
    /*
     * Create an empty structure field class to be used as the
     * event class's payload field class.
     */
    bt_field_class *payload_field_class =
        bt_field_class_structure_create(trace_class);
 
    /*
     * Create a string field class to be used as the payload field
     * class's `msg` member.
     */
    bt_field_class *msg_field_class =
        bt_field_class_string_create(trace_class);
 
    /*
     * Append the string field class to the structure field class as the
     * `msg` member.
     */
    bt_field_class_structure_append_member(payload_field_class, "msg",
        msg_field_class);
 
    /* Set the event class's payload field class */
    bt_event_class_set_payload_field_class(event_class, payload_field_class);
 
    /* Put the references we don't need anymore */
    bt_field_class_put_ref(payload_field_class);
    bt_field_class_put_ref(msg_field_class);
    #endif
    bt_value *attributes = bt_event_class_borrow_user_attributes(event_class);
    bt_value_map_insert_string_entry(attributes, "function", probe->function.c_str());
    bt_value_map_insert_string_entry(attributes, "file", probe->file.c_str());
    bt_value_map_insert_unsigned_integer_entry(attributes, "line", probe->line);

    bt_event_class_put_ref(event_class);
}

/*
 * Creates the source component's metadata and stream objects.
 */
static
void create_metadata_and_stream(bt_self_component *self_component,
        struct xpedite_in *xpedite_in)
{
    /* Create a default trace class */
    bt_trace_class *trace_class = bt_trace_class_create(self_component);

    /* Create a stream trace class within `trace_class` */
    bt_stream_class *stream_class = bt_stream_class_create(trace_class);

    /* Create a default clock class (1 GHz frequency) */
    // TODO: set the clock frequency to the processor frequency?
    bt_clock_class *clock_class = bt_clock_class_create(self_component);
    // TODO: use the clock class to perform the cycles to nanoseconds since
    // epoch computations. It sounds like I need to set offset in seconds
    // since the epoch and the clock frequency: https://babeltrace.org/docs/v2.0/libbabeltrace2/group__api-tir-clock-cls.html#gac3a2f1bf8b2ad3b1e569d47fbb1fcf70

    /*
     * Set `clock_class` as the default clock class of `stream_class`.
     *
     * This means all the streams created from `stream_class` have a
     * conceptual default clock which is an instance of `clock_class`.
     * Any event message created for such a stream has a snapshot of the
     * stream's default clock.
     */
    bt_stream_class_set_default_clock_class(stream_class, clock_class);
    bt_stream_class_set_assigns_automatic_event_class_id(stream_class, BT_FALSE);
    bt_stream_class_set_supports_packets(stream_class, BT_TRUE, BT_TRUE, BT_FALSE);

    /* Create a default trace from (instance of `trace_class`) */
    bt_trace *trace = bt_trace_create(trace_class);
    // TODO: populate trace details from xpedite-appinfo or python

    {
         // define packet context structure
         bt_field_class *packet_context_field_class =
              bt_field_class_structure_create(trace_class);

         bt_field_class *thread_id_field_class = bt_field_class_integer_signed_create(trace_class);
         bt_field_class_structure_append_member(packet_context_field_class, "tid", thread_id_field_class);
         bt_stream_class_set_packet_context_field_class(stream_class, packet_context_field_class);

         /* Put the references we don't need anymore */
         bt_field_class_put_ref(thread_id_field_class);
         bt_field_class_put_ref(packet_context_field_class);
    }

    // automatically define event classes for all probes present in xpedite-appinfo.txt
    for (std::pair<const void *, ProbeInfo> element : xpedite_in->loader->returnSiteMap()) {
         create_event_class(stream_class, &element.second); // TODO: hold onto the event class to destroy it?
    }

    /*
     * Create the source component's stream (instance of `stream_class`
     * within `trace`).
     */
    xpedite_in->stream = bt_stream_create(stream_class, trace);
    // TODO: create a stream for each thread?? does that make sense?

    /* Put the references we don't need anymore */
    bt_trace_put_ref(trace);
    bt_clock_class_put_ref(clock_class);
    bt_stream_class_put_ref(stream_class);
    bt_trace_class_put_ref(trace_class);
}

/*
 * Initializes the source component.
 */
static
bt_component_class_initialize_method_status xpedite_in_initialize(
        bt_self_component_source *self_component_source,
        bt_self_component_source_configuration *configuration,
        const bt_value *params, void *initialize_method_data)
{
    /* Allocate a private data structure */
    struct xpedite_in *xpedite_in = (struct xpedite_in*)calloc(1, sizeof(*xpedite_in));
    xpedite_in->tid = -1; // initialize to -1

    const char *samples_file_path = bt_value_string_get(bt_value_map_borrow_entry_value_const(params, "path"));
    xpedite_in->loader = new SamplesLoader(samples_file_path, bt_value_string_get(bt_value_map_borrow_entry_value_const(params, "appinfo")));

    /* Upcast `self_component_source` to the `bt_self_component` type */
    bt_self_component *self_component =
        bt_self_component_source_as_self_component(self_component_source);

    /* Create the source component's metadata and stream objects */
    create_metadata_and_stream(self_component, xpedite_in);
    const std::regex samples_file_path_regex(".*/xpedite-(.*)-([0-9]+)-([0-9]+)-[^-]+.data");
    std::cout<< "trying to match regex for: "<< samples_file_path << std::endl;;
    std::cmatch samples_file_info_match;
    if (std::regex_match(samples_file_path, samples_file_info_match, samples_file_path_regex)) {
         std::cout<< "matched the regex!\n";
         // TODO: validate that the executable name matches the appinfo
         uint64_t trace_id = stoull(samples_file_info_match[2].str()); // TODO: use
         int32_t thread_id = stol(samples_file_info_match[3].str(), nullptr, 10);
         xpedite_in->tid = thread_id;
    }

    /* Set the component's user data to our private data structure */
    bt_self_component_set_data(self_component, xpedite_in);

    /*
     * Add an output port named `out` to the source component.
     *
     * This is needed so that this source component can be connected to
     * a filter or a sink component. Once a downstream component is
     * connected, it can create our message iterator.
     */
    bt_self_component_source_add_output_port(self_component_source,
        "out", NULL, NULL);

    return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_OK;
}

/*
 * Finalizes the source component.
 */
static
void xpedite_in_finalize(bt_self_component_source *self_component_source)
{
    /* Retrieve our private data from the component's user data */
    struct xpedite_in *xpedite_in = (struct xpedite_in*)bt_self_component_get_data(
        bt_self_component_source_as_self_component(self_component_source));

    delete xpedite_in->loader;
    bt_stream_put_ref(xpedite_in->stream);

    /* Free the allocated structure */
    free(xpedite_in);
}

/*
 * Initializes the message iterator.
 */
static
bt_message_iterator_class_initialize_method_status
xpedite_in_message_iterator_initialize(
        bt_self_message_iterator *self_message_iterator,
        bt_self_message_iterator_configuration *configuration,
        bt_self_component_port_output *self_port)
{
    /* Retrieve the component's private data from its user data */
    struct xpedite_in *xpedite_in = (struct xpedite_in*)bt_self_component_get_data(
        bt_self_message_iterator_borrow_component(self_message_iterator));

    struct xpedite_iter *iter = (struct xpedite_iter*)calloc(1, sizeof(*iter));
    iter->state = ITER_STATE_BEGIN_STREAM;
    /* Allocate a private data structure */
    iter->samples = xpedite_in->loader->begin();

    /* Set the message iterator's user data to our private data structure */
    bt_self_message_iterator_set_data(self_message_iterator, iter);

    return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_OK;
}

/*
 * Finalizes the message iterator.
 */
static
void xpedite_in_message_iterator_finalize(
        bt_self_message_iterator *self_message_iterator)
{
    /* Retrieve our private data from the message iterator's user data */
     struct xpedite_iter *iter =
        (struct xpedite_iter*)bt_self_message_iterator_get_data(self_message_iterator);

    iter->samples.~Iterator();
    free(iter);
}

/*
 * Returns the next message to the message iterator's user.
 *
 * This method can fill the `messages` array with up to `capacity`
 * messages.
 *
 */
static
bt_message_iterator_class_next_method_status xpedite_in_message_iterator_next(
        bt_self_message_iterator *self_message_iterator,
        bt_message_array_const messages, uint64_t capacity,
        uint64_t *count)
{
     *count = 0;
    /* Retrieve our private data from the message iterator's user data */
     struct xpedite_iter *iter =
        (struct xpedite_iter*)bt_self_message_iterator_get_data(self_message_iterator);

    /* Retrieve the component's private data from its user data */
    struct xpedite_in *xpedite_in = (struct xpedite_in*)bt_self_component_get_data(
        bt_self_message_iterator_borrow_component(self_message_iterator));

    auto end = xpedite_in->loader->end();
    while ( *count < capacity ) {
         //std::cout<< "nmessages: " << std::dec << *count << " / " << capacity << std::endl;
         if ( iter->samples == end ) {
              // done collecting samples
              /* Message iterator is ended: return the corresponding status */
              /* Create a stream end message */
              if ( iter->state != ITER_STATE_BEGIN_STREAM ) {
                   if ( iter->packet ) {
                        // TODO: create packet end message and clear the packet pointer
                        messages[(*count)++] = bt_message_packet_end_create(self_message_iterator, iter->packet);
                        BT_PACKET_PUT_REF_AND_RESET(iter->packet); // next time through we will create the stream end message
                   } else {
                        messages[(*count)++] = bt_message_stream_end_create(self_message_iterator, xpedite_in->stream);
                        return BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_END;
                   }
              }
         } else {
              auto &sample = *(iter->samples);
              switch( iter->state ) {
              case ITER_STATE_BEGIN_STREAM: {
                 messages[(*count)++] = bt_message_stream_beginning_create(self_message_iterator, xpedite_in->stream);
                 //std::cout<< "beginning stream 0x" << std::hex << (uintptr_t)messages[*count - 1] << std::endl;
                 iter->first_sample_tsc = ClockTicks(sample.tsc());
                 iter->state = ITER_STATE_APPEND_SAMPLES;
                      // TODO: set the default clock's offset in seconds/figure out how to use the babeltrace clocks
              } break;
              case ITER_STATE_APPEND_SAMPLES: {
                   // create an event
                   uint64_t sample_timestamp = _clock_ticks_to_nanoseconds(iter->first_sample_tsc, ClockTicks(sample.tsc())).count();
                   if ( !iter->packet ) {
                      iter->packet = bt_packet_create(xpedite_in->stream);
                      bt_field *context = bt_packet_borrow_context_field(iter->packet);
                      bt_field_integer_signed_set_value(bt_field_structure_borrow_member_field_by_name(context, "tid"), xpedite_in->tid);
                      iter->packet_roll_timestamp = sample_timestamp + 1000000000ULL; // roll packets over every second
                      messages[(*count)++] = bt_message_packet_beginning_create_with_default_clock_snapshot(self_message_iterator, iter->packet, sample_timestamp);
                   } else if ( sample_timestamp > iter->packet_roll_timestamp ) {
                        messages[(*count)++] = bt_message_packet_end_create(self_message_iterator, iter->packet);
                        BT_PACKET_PUT_REF_AND_RESET(iter->packet); // next time through we will create the stream end message
                   } else {
                        uint64_t event_class_id = (uint64_t)sample.returnSite();
                        const struct bt_event_class *event_class = bt_stream_class_borrow_event_class_by_id_const(bt_stream_borrow_class(xpedite_in->stream), event_class_id);

                        messages[(*count)++] = bt_message_event_create_with_packet_and_default_clock_snapshot(self_message_iterator, event_class, iter->packet, sample_timestamp); // TODO: clock stuff
                        iter->samples++; // advance the samples iterator
                   }
              } break;
              }
         }
    }

    return BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_OK;
}

/* Mandatory */
BT_PLUGIN_MODULE();

/* Define the `xpedite` plugin */
BT_PLUGIN(xpedite);

/* Define the `input` source component class */
BT_PLUGIN_SOURCE_COMPONENT_CLASS(input, xpedite_in_message_iterator_next);

/* Set some of the `input` source component class's optional methods */
BT_PLUGIN_SOURCE_COMPONENT_CLASS_INITIALIZE_METHOD(input, xpedite_in_initialize);
BT_PLUGIN_SOURCE_COMPONENT_CLASS_FINALIZE_METHOD(input, xpedite_in_finalize);
BT_PLUGIN_SOURCE_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD(input,
    xpedite_in_message_iterator_initialize);
BT_PLUGIN_SOURCE_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_FINALIZE_METHOD(input,
    xpedite_in_message_iterator_finalize);

