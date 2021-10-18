package de.kp.works.models.osquery.apps
/*
 * Copyright (c) 2019 - 2021 Dr. Krusche & Partner PartG. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 * @author Stefan Krusche, Dr. Krusche & Partner PartG
 *
 */

import java.math.BigInteger
import java.security.MessageDigest
import scala.collection.mutable

trait BaseApp {

  /**
   * Column names
   */
  val DIRECTORY      = "directory"
  val FAMILY         = "family"
  val FD             = "fd"
  val HOSTNAME       = "hostname"
  val LOCAL_ADDRESS  = "local_address"
  val LOCAL_PORT     = "local_port"
  val NAME           = "name"
  val PATH           = "path"
  val PID            = "pid"
  val PROTOCOL       = "protocol"
  val REMOTE_ADDRESS = "remote_address"
  val REMOTE_PORT    = "remote_port"
  val SOCKET         = "socket"
  val STATE          = "state"
  /**
   * Edge names
   */
  val HAS_HASH   = "has_hash"
  val HAS_CONN   = "has_conn"
  val HAS_SOCKET = "has_socket"

  val md: MessageDigest =
    MessageDigest.getInstance("MD5")
  /**
   * The list of vertex entries extract from a log
   * entry
   */
  val vertices: mutable.ArrayBuffer[Vertex] =
    mutable.ArrayBuffer.empty[Vertex]
  /**
   * The list of edge entries extract from a log
   * entry
   */
  val edges: mutable.ArrayBuffer[Edge] =
    mutable.ArrayBuffer.empty[Edge]

  def buildHash(values:Seq[String]):String = {

    val bytes = values.mkString("|").getBytes
    val digest = md.digest(bytes)

    new BigInteger(1, digest).toString(16)

  }

}
