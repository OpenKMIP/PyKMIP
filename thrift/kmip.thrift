/**
 * This is the thrift definition file. It defines all of the methods and objects
 * for the KMIP server. This file is used by thrift to generate the plumbing for
 * a KMIP client and server.
 *
 * This file generated the files under kmip/thrift.
 *
 * If this file is updated then run the following command to update the
 * kmip/thrift directory.
 *
 * thrift -o kmip -r --gen py thrift/tutorial.thrift
 */

/**
 * The first thing to know about are types. The available types in Thrift are:
 *
 *  bool        Boolean, one byte
 *  byte        Signed byte
 *  i16         Signed 16-bit integer
 *  i32         Signed 32-bit integer
 *  i64         Signed 64-bit integer
 *  double      64-bit floating point value
 *  string      String
 *  binary      Blob (byte array)
 *  map<t1,t2>  Map from one type to another
 *  list<t1>    Ordered list of one type
 *  set<t1>     Set of unique elements of one type
 *
 */

namespace cpp thrift
namespace d thrift
namespace java thrift
namespace php thrift
namespace perl thrift

service KMIP {

   void create(),
   /* Did not use register because it is a reserved word */
   void register_mo()

}