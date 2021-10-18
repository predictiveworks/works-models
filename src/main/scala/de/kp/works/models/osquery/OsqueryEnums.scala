package de.kp.works.models.osquery
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

object OsqueryEnums extends Enumeration{

  type OsqueryEnum = Value

  /* `family` & `protocol` field, extracted from
   * process_open_descriptors.cpp
   *
   * These numbers are equivalent with the
   * linux/socket.h
   */
  val IPv4: OsqueryEnums.Value = Value(2,  "IPv4")
  val IPv6: OsqueryEnums.Value = Value(10, "IPv6")

  val TCP: OsqueryEnums.Value = Value(6,  "TCP")
  val UDP: OsqueryEnums.Value = Value(17, "UDP")

  val FAMILIES = Seq(IPv4, IPv6)
  val PROTOCOLS = Seq(TCP, UDP)

  def familyById(id:Int):String = {

    val families = FAMILIES.filter(v => v.id == id)
    if (families.isEmpty) return null
    families.head.toString

  }

  def protocolById(id:Int):String = {

    val protocols = PROTOCOLS.filter(v => v.id == id)
    if (protocols.isEmpty) return null
    protocols.head.toString

  }
}
