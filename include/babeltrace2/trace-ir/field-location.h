/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2022-2024 EfficiOS Inc. and Linux Foundation
 */

#ifndef BABELTRACE2_TRACE_IR_FIELD_LOCATION_H
#define BABELTRACE2_TRACE_IR_FIELD_LOCATION_H

#ifndef __BT_IN_BABELTRACE_H
# error "Please include <babeltrace2/babeltrace.h> instead."
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*!
@defgroup api-tir-field-loc Field location
@ingroup api-tir

@brief
    Location of a \bt_field.

A <strong><em>field location</em></strong> indicates how to reach a
given \bt_field from a given <em>root scope</em>.

@note
    @parblock
    Unlike a \bt_field_path, which is only available within a
    trace processing \bt_graph with the effective \bt_mip (MIP)
    version&nbsp;0, a field location works with \bt_struct_field member
    <em>names</em>, not with structure field member <em>indexes</em>.

    This makes a field location more versatile than a field path,
    rendering possible, for example, multiple \bt_p_uint_field to act as
    candidates for the length field of a dynamic array field when
    they're part of the same \bt_var_field.

    The field location API is only available within a trace processing
    graph with the effective MIP version&nbsp;1.
    @endparblock

A field location indicates how to reach:

- The length field(s) of a \bt_darray_field (with a length field).
- The selector field of a \bt_opt_field (with a selector field).
- The selector field of a \bt_var_field (with a selector field).

A field location is a \ref api-tir "trace IR" metadata object.

A field location is a \ref api-fund-shared-object "shared object": get a
new reference with bt_field_location_get_ref() and put an existing
reference with bt_field_location_put_ref().

The type of a field location is #bt_field_location.

Create a field location with bt_field_location_create().

<h1>Properties</h1>

A field location has the following properties:

<dl>
  <dt>
    \anchor api-tir-field-loc-prop-root
    Root scope
  </dt>
  <dd>
    Indicates from which \bt_struct_field to start a field location.

    See \ref api-tir-field-loc-proc "Field location procedure" to
    learn more.

    Get the root scope of a field location with
    bt_field_location_get_root_scope().
  </dd>

  <dt>
    \anchor api-tir-field-loc-prop-items
    Items
  </dt>
  <dd>
    Each item in the item list of a field location indicates which
    action to take to follow the location to the linked \bt_field.

    A field location item is a string (a structure field member name).

    See \ref api-tir-field-loc-proc "Field location procedure" to
    learn more.

    Get the number of items in a field location with
    bt_field_location_get_item_count().

    Get an item from a field location with
    bt_field_location_get_item_by_index().

    A field location item always belongs to the field location which
    contains it.
  </dd>
</dl>

<h1>\anchor api-tir-field-loc-proc Field location procedure</h1>

To locate a field from another field \bt_var{SRCFIELD} using
its field location \bt_var{FIELDLOC}:

-# Let \bt_var{CURFIELD} be, depending on the
   root scope of \bt_var{FIELDLOC}
   (as returned by bt_field_location_get_root_scope()):

   <dl>
     <dt>#BT_FIELD_LOCATION_SCOPE_PACKET_CONTEXT</dt>
     <dd>
       What bt_packet_borrow_context_field_const() returns for the
       current \bt_pkt.
     </dd>
     <dt>#BT_FIELD_LOCATION_SCOPE_EVENT_COMMON_CONTEXT</dt>
     <dd>
       What bt_event_borrow_common_context_field_const() returns
       for the current \bt_ev.
     </dd>
     <dt>#BT_FIELD_LOCATION_SCOPE_EVENT_SPECIFIC_CONTEXT</dt>
     <dd>
       What bt_event_borrow_specific_context_field_const() returns
       for the current event.
     </dd>
     <dt>#BT_FIELD_LOCATION_SCOPE_EVENT_PAYLOAD</dt>
     <dd>
       What bt_event_borrow_payload_field_const() returns for the
       current event.
     </dd>
   </dl>

-# For each field location item \bt_var{NAME} in \bt_var{FIELDLOC} (use
   bt_field_location_get_item_count() and
   bt_field_location_get_item_by_index()):

   -# Let \bt_var{CURFIELD} be the field of the structure field
      member named \bt_var{NAME} within \bt_var{CURFIELD}
      (as returned by
      bt_field_structure_borrow_member_field_by_name_const()).

   -# Depending on the class type of \bt_var{CURFIELD} (as returned by
      bt_field_get_class_type()):

      <dl>
        <dt>#BT_FIELD_CLASS_TYPE_BOOL</dt>
        <dt>#BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER</dt>
        <dt>#BT_FIELD_CLASS_TYPE_SIGNED_INTEGER</dt>
        <dt>#BT_FIELD_CLASS_TYPE_UNSIGNED_ENUMERATION</dt>
        <dt>#BT_FIELD_CLASS_TYPE_SIGNED_ENUMERATION</dt>
        <dd>End the field location procedure.</dd>

        <dt>#BT_FIELD_CLASS_TYPE_STRUCTURE</dt>
        <dd>Continue.</dd>

        <dt>#BT_FIELD_CLASS_TYPE_STATIC_ARRAY</dt>
        <dt>#BT_FIELD_CLASS_TYPE_DYNAMIC_ARRAY_WITHOUT_LENGTH_FIELD</dt>
        <dt>#BT_FIELD_CLASS_TYPE_DYNAMIC_ARRAY_WITH_LENGTH_FIELD</dt>
        <dd>
           While the class type of \bt_var{CURFIELD} is one of the
           three above (that is, while \bt_var{CURFIELD} i
           an array field):

           - Set \bt_var{CURFIELD} to the element field of
             \bt_var{CURFIELD} (as returned by
             bt_field_array_borrow_element_field_by_index_const())
             containing \bt_var{SRCFIELD}.
        </dd>

        <dt>#BT_FIELD_CLASS_TYPE_OPTION_WITHOUT_SELECTOR_FIELD</dt>
        <dt>#BT_FIELD_CLASS_TYPE_OPTION_WITH_BOOL_SELECTOR_FIELD</dt>
        <dt>#BT_FIELD_CLASS_TYPE_OPTION_WITH_UNSIGNED_INTEGER_SELECTOR_FIELD</dt>
        <dt>#BT_FIELD_CLASS_TYPE_OPTION_WITH_SIGNED_INTEGER_SELECTOR_FIELD</dt>
        <dd>
          Set \bt_var{CURFIELD} to the optional field of
          \bt_var{CURFIELD} (as returned by
          bt_field_option_borrow_field_const()).
        </dd>

        <dt>#BT_FIELD_CLASS_TYPE_VARIANT_WITHOUT_SELECTOR_FIELD</dt>
        <dt>#BT_FIELD_CLASS_TYPE_VARIANT_WITH_UNSIGNED_INTEGER_SELECTOR_FIELD</dt>
        <dt>#BT_FIELD_CLASS_TYPE_VARIANT_WITH_SIGNED_INTEGER_SELECTOR_FIELD</dt>
        <dd>
          Set \bt_var{CURFIELD} to the selected option field of
          \bt_var{CURFIELD} (as returned by
          bt_field_variant_borrow_selected_option_field_const()).
        </dd>
      </dl>

After this procedure, \bt_var{CURFIELD} is the located field.
*/

/*! @{ */

/*!
@brief
    Field location scope enumerators.
*/
typedef enum bt_field_location_scope {
	/*!
	@brief
	    Context of the current \bt_pkt.
	*/
	BT_FIELD_LOCATION_SCOPE_PACKET_CONTEXT		= 0,

	/*!
	@brief
	    Common context of the current \bt_ev.
	*/
	BT_FIELD_LOCATION_SCOPE_EVENT_COMMON_CONTEXT	= 1,

	/*!
	@brief
	    Specific context of the current event.
	*/
	BT_FIELD_LOCATION_SCOPE_EVENT_SPECIFIC_CONTEXT	= 2,

	/*!
	@brief
	    Payload of the current event.
	*/
	BT_FIELD_LOCATION_SCOPE_EVENT_PAYLOAD		= 3,
} bt_field_location_scope;

/*!
@brief
    Creates a field location from the trace class \bt_p{trace_class}
    using the scope \bt_p{scope} and the items \bt_p{items}.

@param[in] trace_class
    Trace class from which to create a field location.
@param[in] root_scope
    \link api-tir-field-loc-prop-root Root scope\endlink of the
    field location to create.
@param[in] items
    @parblock
    \link api-tir-field-loc-prop-items Items\endlink (copied) of the
    field location to create.

    \bt_p{item_count} is the number of elements in \bt_p{items}.
    @endparblock
@param[in] item_count
    Number of elements in \bt_p{items}.

@returns
    New field location reference, or \c NULL on memory error.

@bt_pre_not_null{trace_class}
@bt_pre_tc_with_mip{trace_class, 0}
@bt_pre_not_null{items}
@pre
    \bt_p{item_count}&nbsp;≥&nbsp;1.
*/
extern bt_field_location *bt_field_location_create(
		bt_trace_class *trace_class,
		bt_field_location_scope root_scope,
		const char *const *items,
		uint64_t item_count) __BT_NOEXCEPT;

/*!
@brief
    Returns the root scope of the field location \bt_p{field_location}.

See the \ref api-tir-field-loc-prop-root "root scope" property.

@param[in] field_location
    Field location of which to get the root scope.

@returns
    Root scope of \bt_p{field_location}.

@bt_pre_not_null{field_location}
*/
extern bt_field_location_scope bt_field_location_get_root_scope(
		const bt_field_location *field_location) __BT_NOEXCEPT;

/*!
@brief
    Returns the number of items contained in the field location
    \bt_p{field_location}.

See the \ref api-tir-field-loc-prop-items "items" property.

@param[in] field_location
    Field location of which to get the number of contained items.

@returns
    Number of contained items in \bt_p{field_location}.

@bt_pre_not_null{field_location}

@sa bt_field_location_get_item_by_index() &mdash;
    Returns an item by index from a field location.
*/
extern uint64_t bt_field_location_get_item_count(
		const bt_field_location *field_location) __BT_NOEXCEPT;

/*!
@brief
    Borrows the item at index \bt_p{index} from the
    field location \bt_p{field_location}.

See the \ref api-tir-field-loc-prop-items "items" property.

@param[in] field_location
    Field location from which to borrow the item at index \bt_p{index}.
@param[in] index
    Index of the item to borrow from \bt_p{field_location}.

@returns
    @parblock
    Item of \bt_p{field_location} at index \bt_p{index}.

    The returned pointer remains valid as long as \bt_p{field_location}
    exists.
    @endparblock

@bt_pre_not_null{field_location}
@pre
    \bt_p{index} is less than the number of items in
    \bt_p{field_location}
    (as returned by bt_field_location_get_item_count()).

@sa bt_field_location_get_item_count() &mdash;
    Returns the number of items contained in a field location.
*/
extern const char *bt_field_location_get_item_by_index(
		const bt_field_location *field_location,
		uint64_t index) __BT_NOEXCEPT;

/*!
@brief
    Increments the \ref api-fund-shared-object "reference count" of
    the field location \bt_p{field_location}.

@param[in] field_location
    @parblock
    Field location of which to increment the reference count.

    Can be \c NULL.
    @endparblock

@sa bt_field_location_put_ref() &mdash;
    Decrements the reference count of a field location.
*/
extern void bt_field_location_get_ref(
		const bt_field_location *field_location) __BT_NOEXCEPT;

/*!
@brief
    Decrements the \ref api-fund-shared-object "reference count" of
    the field location \bt_p{field_location}.

@param[in] field_location
    @parblock
    Field location of which to decrement the reference count.

    Can be \c NULL.
    @endparblock

@sa bt_field_location_get_ref() &mdash;
    Increments the reference count of a field location.
*/
extern void bt_field_location_put_ref(
		const bt_field_location *field_location) __BT_NOEXCEPT;

/*!
@brief
    Decrements the reference count of the field location
    \bt_p{_field_location}, and then sets \bt_p{_field_location} to
    \c NULL.

@param _field_location
    @parblock
    Field location of which to decrement the reference count.

    Can contain \c NULL.
    @endparblock

@bt_pre_assign_expr{_field_location}
*/
#define BT_FIELD_LOCATION_PUT_REF_AND_RESET(_field_location)	\
	do {							\
		bt_field_location_put_ref(_field_location);	\
		(_field_location) = NULL;			\
	} while (0)

/*!
@brief
    Decrements the reference count of the field location \bt_p{_dst},
    sets \bt_p{_dst} to \bt_p{_src}, and then sets \bt_p{_src}
    to \c NULL.

This macro effectively moves a field location reference from the
expression \bt_p{_src} to the expression \bt_p{_dst}, putting the
existing \bt_p{_dst} reference.

@param _dst
    @parblock
    Destination expression.

    Can contain \c NULL.
    @endparblock
@param _src
    @parblock
    Source expression.

    Can contain \c NULL.
    @endparblock

@bt_pre_assign_expr{_dst}
@bt_pre_assign_expr{_src}
*/
#define BT_FIELD_LOCATION_MOVE_REF(_dst, _src)		\
	do {						\
		bt_field_location_put_ref(_dst);	\
		(_dst) = (_src);			\
		(_src) = NULL;				\
	} while (0)

/*! @} */

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE2_TRACE_IR_FIELD_LOCATION_H */
