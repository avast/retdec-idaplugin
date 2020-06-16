
#ifndef RETDEC_PLACE_H
#define RETDEC_PLACE_H

#include <iostream>

#include "context.h"
#include "yx.h"
#include "function.h"

/**
 * Denotes a displayed line.
 *
 * An object may be displayed on one or more lines. All lines of an object are
 * generated at once and kept in a linearray_t class.
 */
class retdec_place_t : public place_t
{
	// Inherited from place_t.
	//
	public:
		/// Generate a short description of the location.
		/// This description is used on the status bar.
		/// \param out_buf  the output buffer
		/// \param ud       pointer to user-defined context data.
		///                 Is supplied by ::linearray_t
		virtual void idaapi print(qstring* out_buf, void* ud) const override;

		/// Map the location to a number.
		/// This mapping is used to draw the vertical scrollbar.
		/// \param ud  pointer to user-defined context data.
		///            Is supplied by ::linearray_t
		virtual uval_t idaapi touval(void* ud) const override;

		/// Clone the location.
		/// \return a pointer to a copy of the current location in dynamic
		///         memory
		virtual place_t* idaapi clone(void) const override;

		/// Copy the specified location object to the current object
		virtual void idaapi copyfrom(const place_t* from) override;

		/// Map a number to a location.
		/// When the user clicks on the scrollbar and drags it, we need to
		/// determine the location corresponding to the new scrollbar position.
		/// This function is used to determine it. It builds a location object
		/// for the specified 'x' and returns a pointer to it.
		/// \param ud     pointer to user-defined context data.
		///               Is supplied by ::linearray_t
		/// \param x      number to map
		/// \param lnnum  line number to initialize 'lnnum'
		/// \return a static object, no need to destroy it.
		virtual place_t* idaapi makeplace(
				void* ud,
				uval_t y,
				int lnnum) const override;

		/// Deprecated. Please consider compare2(const place_t *, void *) instead.
		virtual int idaapi compare(const place_t* t2) const override;

		/// Compare two locations except line numbers (lnnum).
		/// This function is used to organize loops.
		/// For example, if the user has selected an range, its boundaries are remembered
		/// as location objects. Any operation within the selection will have the following
		/// look: for ( loc=starting_location; loc < ending_location; loc.next() )
		/// In this loop, the comparison function is used.
		/// \param t2 the place to compare this one to.
		/// \param ud pointer to user-defined context data.
		/// \retval -1 if the current location is less than 't2'
		/// \retval  0 if the current location is equal to than 't2'
		/// \retval  1 if the current location is greater than 't2'
		virtual int idaapi compare2(const place_t* t2, void* ud) const override;

		/// Adjust the current location to point to a displayable object.
		/// This function validates the location and makes sure that it points
		/// to an existing object. For example, if the location points to the
		/// middle of an instruction, it will be adjusted to point to the
		/// beginning of the instruction.
		/// \param ud  pointer to user-defined context data.
		///            Is supplied by ::linearray_t
		virtual void idaapi adjust(void* ud) override;

		/// Move to the previous displayable location.
		/// \param ud  pointer to user-defined context data.
		///            Is supplied by ::linearray_t
		/// \return success
		virtual bool idaapi prev(void* ud) override;

		/// Move to the next displayable location.
		/// \param ud  pointer to user-defined context data.
		///            Is supplied by ::linearray_t
		/// \return success
		virtual bool idaapi next(void* ud) override;

		/// Are we at the first displayable object?.
		/// \param ud   pointer to user-defined context data.
		///             Is supplied by ::linearray_t
		/// \return true if the current location points to the first
		///         displayable object
		virtual bool idaapi beginning(void* ud) const override;

		/// Are we at the last displayable object?.
		/// \param ud   pointer to user-defined context data.
		///             Is supplied by ::linearray_t
		/// \return true if the current location points to the last
		///         displayable object
		virtual bool idaapi ending(void* ud) const override;

		/// Generate text lines for the current location.
		/// \param out            storage for the lines
		/// \param out_deflnnum   pointer to the cell that will contain the num
		///                       of the most 'interesting' generated line
		/// \param out_pfx_color  pointer to the cell that will contain the
		///                       line prefix color
		/// \param out_bgcolor    pointer to the cell that will contain the
		///                       background color
		/// \param ud             pointer to user-defined context data.
		///                       Is supplied by linearray_t
		/// \param maxsize        the maximum number of lines to generate
		/// \return number of generated lines
		virtual int idaapi generate(
				qstrvec_t* out,
				int* out_deflnnum,
				color_t* out_pfx_color,
				bgcolor_t* out_bgcolor,
				void* ud,
				int maxsize) const override;

		/// Serialize this instance.
		/// It is fundamental that all instances of a particular subclass
		/// of of place_t occupy the same number of bytes when serialized.
		/// \param out   buffer to serialize into
		virtual void idaapi serialize(bytevec_t* out) const override;

		/// De-serialize into this instance.
		/// 'pptr' should be incremented by as many bytes as
		/// de-serialization consumed.
		/// \param pptr pointer to a serialized representation of a place_t
		///             of this type.
		/// \param end pointer to end of buffer.
		/// \return whether de-serialization was successful
		virtual bool idaapi deserialize(
				const uchar** pptr,
				const uchar* end) override;

		/// Get the place's ID (i.e., the value returned by
		/// register_place_class())
		/// \return the id
		virtual int idaapi id() const override;

		/// Get this place type name.
		/// All instances of a given class must return the same string.
		/// \return the place type name. Please try and pick something that is
		///         not too generic, as it might clash w/ other plugins. A good
		///         practice is to prefix the class name with the name
		///         of your plugin. E.g., "myplugin:srcplace_t".
		virtual const char* idaapi name() const override;

		/// Map the location to an ea_t.
		/// \return the corresponding ea_t, or BADADDR;
		virtual ea_t idaapi toea() const override;

		/// Rebase the place instance
		/// \param infos the segments that were moved
		/// \return true if place was rebased, false otherwise
		virtual bool idaapi rebase(const segm_move_infos_t&) override;

		/// Visit this place, possibly 'unhiding' a section of text.
		/// If entering that place required some expanding, a place_t
		/// should be returned that represents that section, plus some
		/// flags for later use by 'leave()'.
		/// \param out_flags flags to be used together with the place_t that is
		///                  returned, in order to restore the section to its
		///                  original state when leave() is called.
		/// \return a place_t corresponding to the beginning of the section
		///         of text that had to be expanded. That place_t's leave() will
		///         be called with the flags contained in 'out_flags' when the
		///         user navigates away from it.
		virtual place_t* idaapi enter(uint32*) const override;

		/// Leave this place, possibly 'hiding' a section of text that was
		/// previously expanded (at enter()-time.)
		virtual void idaapi leave(uint32) const override;

	public:
		static int ID;

		retdec_place_t(Function* fnc, YX yx);
		static void registerPlace(const plugin_t& PLUGIN);

		YX yx() const;
		std::size_t y() const;
		std::size_t x() const;
		const Token* token() const;
		Function* fnc() const;

		std::string toString() const;
		friend std::ostream& operator<<(
				std::ostream& os,
				const retdec_place_t& p
		);

	private:
		inline static const char* _name = "retdec_place_t";

		Function* _fnc = nullptr;
		YX _yx;
};

/// Converts from an entry with a given place type, to another entry,
/// with another place type, to be used with the view 'view'. Typically
/// used when views are synchronized.
/// The 'renderer_info_t' part of 'dst' will be pre-filled with
/// the current renderer_info_t of 'view', while the 'place_t' instance
/// will always be NULL.
///
/// lochist_entry_cvt_t
///
lecvt_code_t idaapi place_converter(
        lochist_entry_t* dst,
        const lochist_entry_t& src,
        TWidget* view
);

#endif
