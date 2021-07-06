package de.hpi.spark_tutorial

import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.Row
import org.apache.spark.sql.DataFrame
import org.apache.spark.sql.functions._


// This implementation is basically a re-implementation of Sindy,
// heavily inspired by the paper of Kruse, Papenbrock and Naumann:
// https://hpi.de/fileadmin/user_upload/fachgebiete/naumann/publications/2015/Scaling_out_the_discovery_of_INDs-CR.pdf
object Sindy {

  def discoverINDs(inputs: List[String], spark: SparkSession): Unit = {
    import spark.implicits._

    // Step 0: Read input files.
    val inputData = inputs.map(filename => spark.read
      .option("inferSchema", "true")
      .option("header", "true")
      .option("delimiter", ";")
      .csv(filename)
    )
    
    // Step 1: Calculate attribute sets.
    // Step 1.1: Calculate reversed index.
    val reversed = inputData.map { df =>
      df
        .flatMap((row: Row) => {
          val columns = row.schema.names.toSeq
          // TODO: do not use strings here.
          row.toSeq.map(_.toString).zip(columns)
        })
        .toDF("value", "column_name")
        .distinct()
    }.toSeq

    // Step 1.2 Collect set of attributes according to the grouped value.
    val joinedIndex = reversed
      .reduce((d1, d2) => {
        d1.union(d2)
      })
      .groupBy("value")
      .agg(collect_set($"column_name") as "column_names")
      .drop("value")
      .distinct()

    // Step 2: Check for inclusions.
    val inclusionLists = joinedIndex
      .flatMap((row) => {
        val columnNames = row.getSeq[String](row.fieldIndex("column_names"))
        columnNames
          .combinations(columnNames.length - 1)
          .map((combination) => (columnNames.diff(combination).seq(0), combination))
      })
      .toDF("dependent", "referenced")
      .groupBy("dependent")
      // Taken from: https://stackoverflow.com/questions/66207393/how-can-i-conduct-an-intersection-of-multiple-arrays-into-single-array-on-pyspar
      .agg(expr("aggregate(collect_list(referenced), collect_list(referenced)[0], (acc, x) -> array_intersect(acc, x)) as referenced"))
      .filter(size($"referenced") > 0)
      .orderBy("dependent")

    // Step 3: Output.
    inclusionLists.collect().foreach((row) => {
      val dependent = row.getString(row.fieldIndex("dependent"))
      val referenced = row.getSeq[String](row.fieldIndex("referenced"))
      println(dependent + " < " + referenced.mkString(", "))
    })
  }
}
