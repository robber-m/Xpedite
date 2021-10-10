////////////////////////////////////////////////////////////////////////////////////
//
// Babeltrace Xpedite Plugin 
//
// Xpedite probes store timing and performance counter data using variable 
// length POD objects. A collection of sample objects is grouped and written
// as a batch. 
// 
// source.xpedite.input - loads probe sample data from binary files
//
//   Iterate through the POD collection, to extract records into the Babeltrace
//   framework for display, manipulation, filtering, or conversion to alternative
//   trace formats (e.g. CTF) for use with open source profile-data analysis
//   environments (e.g. Trace-Compass).
//
// Author: Robert McShane, Redline Trading Solutions, Inc.
//
////////////////////////////////////////////////////////////////////////////////////

#include <xpedite/framework/SamplesLoader.H>
#include <iostream>
#include <iomanip>
#include <ios>
#include <chrono>
#include "user_data_decoder.H"
using namespace xpedite::probes;
using namespace xpedite::framework;


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
     bool initialized;
     IterState_t state;
     bt_packet *packet;
     uint64_t packet_roll_tsc;
     SamplesLoader::Iterator samples;
     timespec segment_start_time;
};

// TODO: move to a plugin system where users can provide their own probe-data decoders
#define POPULATE_PRODUCT_PROBE_SPECIFIC_FIELDS

/*
 * Creates an event class within `stream_class` for the provided `probe`.
 */
void create_event_class(bt_stream_class *stream_class, ProbeInfo *probe)
{

    /* Create a default event class */
    bt_event_class *event_class = bt_event_class_create_with_id(stream_class, (uint64_t)probe->recorder_return_site);

    /* Name the event class */
    bt_event_class_set_name(event_class, probe->name.c_str());


    #ifdef POPULATE_PRODUCT_PROBE_SPECIFIC_FIELDS
    // declare specific fields for this event class
    {
         // TODO: move this decoder to a plugin-like system which defines the
         // field class for this event type and a decoder function to decode fields into the context
         if ( !strcmp( bt_event_class_get_name(event_class), "ProcessPayloadStart" ) ) {
              bt_trace_class *trace_class = bt_stream_class_borrow_trace_class(stream_class);
              bt_field_class *event_specific_context_field_class = bt_field_class_structure_create(trace_class);


              bt_field_class *packet_receive_time = bt_field_class_integer_signed_create(trace_class);
              bt_field_class_structure_append_member(event_specific_context_field_class, "packetReceiveTime", packet_receive_time);

              bt_field_class *feed = bt_field_class_integer_signed_create(trace_class);
              bt_field_class_structure_append_member(event_specific_context_field_class, "feed", feed);

              bt_field_class *line = bt_field_class_integer_signed_create(trace_class);
              bt_field_class_structure_append_member(event_specific_context_field_class, "line", line);

              bt_field_class *sequence_number = bt_field_class_integer_signed_create(trace_class);
              bt_field_class_structure_append_member(event_specific_context_field_class, "sequenceNumber", sequence_number);

              bt_event_class_set_specific_context_field_class(event_class, event_specific_context_field_class);


              bt_field_class_put_ref(packet_receive_time);
              bt_field_class_put_ref(feed);
              bt_field_class_put_ref(line);
              bt_field_class_put_ref(sequence_number);
              bt_field_class_put_ref(event_specific_context_field_class);
         }
    }
    #endif

    bt_value *attributes = bt_event_class_borrow_user_attributes(event_class);
    {
         bt_value_map_insert_string_entry(attributes, "bin", "xpedite-application");
         bt_value_map_insert_string_entry(attributes, "func", probe->function.c_str());
         std::ostringstream src_string;
         src_string << probe->file << ":" << probe->line;
         bt_value_map_insert_string_entry(attributes, "src", src_string.str().c_str());
    }

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

    bt_clock_class *clock_class = bt_clock_class_create(self_component);
    /* Create a default clock class (processor frequency) */
    bt_clock_class_set_frequency(clock_class, xpedite_in->loader->tscHz());
    // use the clock class to perform the cycles to nanoseconds since epoch computations
    bt_clock_class_set_origin_is_unix_epoch(clock_class, BT_TRUE); // we will use clock_class->offset to align origin to the UNIX epoch

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
    bt_stream_class_set_supports_packets(stream_class, BT_TRUE, BT_TRUE, BT_TRUE);

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

    #ifdef POPULATE_DEBUG_INFO
    // declare common fields across all stream events
    {
         // TODO: only populate these details if debug info is enabled
         bt_field_class *event_common_context_field_class =
              bt_field_class_structure_create(trace_class);

         bt_field_class *debug_info_field_class = bt_field_class_structure_create(trace_class);
         {
              // TODO: pull binary, port, and pid from the appinfo file
              bt_field_class *bin_field_class = bt_field_class_string_create(trace_class);
              bt_field_class_structure_append_member(debug_info_field_class, "bin", bin_field_class);
              bt_field_class_put_ref(bin_field_class);

              bt_field_class *func_field_class = bt_field_class_string_create(trace_class);
              bt_field_class_structure_append_member(debug_info_field_class, "func", func_field_class);
              bt_field_class_put_ref(func_field_class);

              bt_field_class *src_field_class = bt_field_class_string_create(trace_class);
              bt_field_class_structure_append_member(debug_info_field_class, "src", src_field_class);
              bt_field_class_put_ref(src_field_class);
         }
         bt_field_class_structure_append_member(event_common_context_field_class, "debug_info", debug_info_field_class);
         bt_field_class_put_ref(debug_info_field_class);

         bt_stream_class_set_event_common_context_field_class(stream_class, event_common_context_field_class);

         /* Put the references we don't need anymore */
         bt_field_class_put_ref(event_common_context_field_class);
    }
    #endif

    // automatically define event classes for all probes present in xpedite-appinfo.txt
    for (std::pair<const void *, ProbeInfo> element : xpedite_in->loader->returnSiteMap()) {
         create_event_class(stream_class, &element.second); // TODO: hold onto the event class to destroy it?
    }

    /* Create a default trace from (instance of `trace_class`) */
    bt_trace *trace = bt_trace_create(trace_class);

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
    //std::cout<< "trying to match regex for: "<< samples_file_path << std::endl;;
    std::cmatch samples_file_info_match;
    if (std::regex_match(samples_file_path, samples_file_info_match, samples_file_path_regex)) {
         //std::cout<< "matched the regex!\n";
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
 * Seeks to the beginning of the message stream for the associated iterator input source
 */
static bt_message_iterator_class_seek_beginning_method_status xpedite_in_message_iterator_seek_beginning(bt_self_message_iterator *self_message_iterator) {
    /* Retrieve the component's private data from its user data */
    struct xpedite_iter *iter = (struct xpedite_iter*)bt_self_message_iterator_get_data(self_message_iterator);
    struct xpedite_in *xpedite_in = (struct xpedite_in*)bt_self_component_get_data(
        bt_self_message_iterator_borrow_component(self_message_iterator));

    iter->state = ITER_STATE_BEGIN_STREAM;
    if ( iter->packet ) {
        // discard existing packet if in the middle of creating one
        BT_PACKET_PUT_REF_AND_RESET(iter->packet); // next time through we will create the stream end message
    }

    if ( iter->initialized ) {
        iter->samples.~Iterator();
    }

    iter->samples = xpedite_in->loader->begin();
    iter->initialized = true;
    return BT_MESSAGE_ITERATOR_CLASS_SEEK_BEGINNING_METHOD_STATUS_OK;
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

    bt_self_message_iterator_configuration_set_can_seek_forward(configuration, BT_TRUE);

    /* Allocate a private data structure */
    struct xpedite_iter *iter = (struct xpedite_iter*)calloc(1, sizeof(*iter));
    iter->initialized = false;
    /* Set the message iterator's user data to our private data structure */
    bt_self_message_iterator_set_data(self_message_iterator, iter);

    // TODO: consider returning AGAIN, checking for intterupts and looping for big seeks?
    // TODO: does my packet need to emit a timestamp that exactly matches the seek time??
    if ( xpedite_in_message_iterator_seek_beginning(self_message_iterator) != BT_MESSAGE_ITERATOR_CLASS_SEEK_BEGINNING_METHOD_STATUS_OK ) {
        free(iter);
        return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
    }

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

    auto clock_class = bt_stream_class_borrow_default_clock_class(bt_stream_borrow_class(xpedite_in->stream));

    auto end = xpedite_in->loader->end();
    while ( *count < capacity ) {
         if ( iter->samples == end ) {
              // done collecting samples
              /* Message iterator is ended: return the corresponding status */
              /* Create a stream end message */
              if ( iter->state != ITER_STATE_BEGIN_STREAM ) {
                   if ( iter->packet ) {
                        // TODO: create packet end message and clear the packet pointer
                        messages[(*count)++] = bt_message_packet_end_create_with_default_clock_snapshot(self_message_iterator, iter->packet, iter->packet_roll_tsc);
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
                 iter->state = ITER_STATE_APPEND_SAMPLES;
                 {
                     // TODO: re-align the clock to POSIX each time we process
                     // a new recorded segment? Maybe should keep adjusting the
                     // cycles since second value as we get more information?
                     // or maybe up-front we could grab the first few segments
                     // and take the average of the three, using it for the posix time?
                     auto new_segment_start_time = iter->samples.segmentStartTime();
                     if ( (iter->segment_start_time.tv_nsec != new_segment_start_time.tv_nsec) ||
                          (iter->segment_start_time.tv_sec != new_segment_start_time.tv_sec) ) {

                         auto clock_frequency = bt_clock_class_get_frequency(clock_class);
                         int64_t seconds_since_tsc_origin = sample.tsc() / clock_frequency;
                         int64_t posix_seconds_offset = (int64_t)new_segment_start_time.tv_sec - seconds_since_tsc_origin;
                         auto cycles_since_second = (uint64_t)new_segment_start_time.tv_nsec * clock_frequency / 1000000000ULL;
                         #if 0
                         while ( XPEDITE_UNLIKELY(cycles_since_second >= clock_frequency) ) {
                             // TODO: decide on the best way to handle if our originally-estimated frequency drifts from the actual frequency
                             cycles_since_second -= clock_frequency;
                             posix_seconds_offset++;
                         }
                         #endif
                         bt_clock_class_set_offset(clock_class, posix_seconds_offset, cycles_since_second);

                         // update cached value
                         iter->segment_start_time.tv_nsec = new_segment_start_time.tv_nsec;
                         iter->segment_start_time.tv_sec = new_segment_start_time.tv_sec;
                     }
                 }
              } break;
              case ITER_STATE_APPEND_SAMPLES: {
                   // create an event
                   if ( !iter->packet ) {
                      iter->packet = bt_packet_create(xpedite_in->stream);
                      bt_field *context = bt_packet_borrow_context_field(iter->packet);
                      bt_field_integer_signed_set_value(bt_field_structure_borrow_member_field_by_name(context, "tid"), xpedite_in->tid);
                      // TODO: consider instead modeling Xpedite segments as packets?
                      iter->packet_roll_tsc = sample.tsc() + bt_clock_class_get_frequency(clock_class); // roll packets over every second. TODO: consider a different heuristic for this. Maybe one "packet" per "segment"?
                      messages[(*count)++] = bt_message_packet_beginning_create_with_default_clock_snapshot(self_message_iterator, iter->packet, sample.tsc());
                   } else if ( sample.tsc() > iter->packet_roll_tsc ) {
                        messages[(*count)++] = bt_message_packet_end_create_with_default_clock_snapshot(self_message_iterator, iter->packet, iter->packet_roll_tsc);
                        BT_PACKET_PUT_REF_AND_RESET(iter->packet); // next time through we will create the stream end message
                   } else {
                        uint64_t event_class_id = (uint64_t)sample.returnSite();
                        const struct bt_event_class *event_class = bt_stream_class_borrow_event_class_by_id_const(bt_stream_borrow_class(xpedite_in->stream), event_class_id);

                        bt_message *message = bt_message_event_create_with_packet_and_default_clock_snapshot(self_message_iterator, event_class, iter->packet, sample.tsc());
                        #ifdef POPULATE_DEBUG_INFO
                        {
                             // set debug info associated with this event
                             const bt_value *attributes = bt_event_class_borrow_user_attributes_const(event_class);
                             bt_field *common_context = bt_event_borrow_common_context_field(bt_message_event_borrow_event(message));
                             bt_field *debug_info = bt_field_structure_borrow_member_field_by_name(common_context, "debug_info");
                             bt_field_string_set_value(bt_field_structure_borrow_member_field_by_name(debug_info, "bin"),
                                                       bt_value_string_get(bt_value_map_borrow_entry_value_const(attributes, "bin")));
                             bt_field_string_set_value(bt_field_structure_borrow_member_field_by_name(debug_info, "func"),
                                                       bt_value_string_get(bt_value_map_borrow_entry_value_const(attributes, "func")));
                             bt_field_string_set_value(bt_field_structure_borrow_member_field_by_name(debug_info, "src"),
                                                       bt_value_string_get(bt_value_map_borrow_entry_value_const(attributes, "src")));
                        }
                        #endif

                        #ifdef POPULATE_PRODUCT_PROBE_SPECIFIC_FIELDS
                        // TODO: move this to a babeltrace filter plugin which is product-specific and knows how to decode probe user data
                        if ( sample.hasData() && !strcmp( bt_event_class_get_name(event_class), "ProcessPayloadStart" ) ) {
                             auto sample_data = sample.data();
                             __uint128_t metadata = std::get<0>(sample_data);
                             PacketFingerprint_t *packet_fingerprint = (PacketFingerprint_t*)&metadata;
                             uint64_t packet_receive_timestamp = std::get<1>(sample_data);
                             // set user-provided metadata associated with this event
                             bt_field *event_context = bt_event_borrow_specific_context_field(bt_message_event_borrow_event(message));
                             bt_field_integer_unsigned_set_value(bt_field_structure_borrow_member_field_by_name(event_context, "packetReceiveTime"), packet_receive_timestamp);


                             // TODO: set mapped labels for feed ids to map to their corresponding InRush name during initialization
                             bt_field_integer_unsigned_set_value(bt_field_structure_borrow_member_field_by_name(event_context, "feed"),
                                                       packet_fingerprint->feed);
                             bt_field_integer_unsigned_set_value(bt_field_structure_borrow_member_field_by_name(event_context, "line"),
                                                       packet_fingerprint->line);
                             bt_field_integer_unsigned_set_value(bt_field_structure_borrow_member_field_by_name(event_context, "sequenceNumber"),
                                                       packet_fingerprint->sequence_number);
                        }
                        #endif
                        messages[(*count)++] = message;
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
BT_PLUGIN_SOURCE_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_SEEK_BEGINNING_METHODS(input,
    xpedite_in_message_iterator_seek_beginning, NULL);
