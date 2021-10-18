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

case class Edge(
  id:String,
  idType:String,
  label:String,
  toId:String,
  toIdType:String,
  fromId:String,
  fromIdType:String,
  /*
   * The time management of the
   * vertex entry
   */
  createdAt:Option[Long] = None,
  updatedAt:Option[Long] = None,
  /*
   * The properties of the edge
   */
  properties:Option[Map[String,Seq[String]]] = None)
